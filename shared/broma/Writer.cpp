#include "Writer.hpp"
#include <fstream>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <fmt/std.h>

using namespace geode;

namespace bromascan {
    Result<> writeBromaFile(std::filesystem::path const& path, broma::Root const& root) {
        std::ofstream file(path);
        if (!file.is_open()) {
            return Err(fmt::format("Failed to open Broma output file: {}", path));
        }

        GEODE_UNWRAP_INTO(auto str, formatBromaFile(root));
        file << str;

        return Ok();
    }

    struct CommentedClass {
        broma::Class cls;
        std::vector<broma::Comment> leadingComments;
        std::vector<broma::Comment> trailingComments;
    };

    struct CommentedFunction {
        broma::Function fn;
        std::vector<broma::Comment> leadingComments;
        std::vector<broma::Comment> trailingComments;
    };

    struct ASTNodeRef {
        size_t line;
        std::variant<CommentedClass*, CommentedFunction*> ptr;

        void addLeading(broma::Comment const& c) {
            std::visit([&](auto* p) { p->leadingComments.push_back(c); }, ptr);
        }

        void addTrailing(broma::Comment const& c) {
            std::visit([&](auto* p) { p->trailingComments.push_back(c); }, ptr);
        }
    };

    struct FormattedRoot {
        std::vector<CommentedClass> classes;
        std::vector<CommentedFunction> functions;
        std::vector<broma::Comment> fileComments;
    };

    static FormattedRoot attachComments(broma::Root const& root) {
        FormattedRoot res;
        res.classes.reserve(root.classes.size());
        res.functions.reserve(root.functions.size());

        for (auto& cls : root.classes) {
            res.classes.push_back({cls, {}, {}});
        }

        for (auto& fn : root.functions) {
            res.functions.push_back({fn, {}, {}});
        }

        std::vector<ASTNodeRef> timeline;
        timeline.reserve(res.classes.size() + res.functions.size());

        for (auto& c : res.classes) {
            timeline.push_back({c.cls.line, &c});
        }

        for (auto& f : res.functions) {
            timeline.push_back({f.fn.line, &f});
        }

        std::ranges::sort(timeline, [](ASTNodeRef const& a, ASTNodeRef const& b) {
            return a.line < b.line;
        });

        for (auto const& comment : root.comments) {
            auto it = std::upper_bound(
                timeline.begin(), timeline.end(), comment.line,
                [](size_t line, ASTNodeRef const& node) {
                    return line < node.line;
                }
            );

            if (comment.trailing) {
                if (it != timeline.begin()) {
                    std::prev(it)->addTrailing(comment);
                } else {
                    res.fileComments.push_back(comment);
                }
            } else {
                if (it != timeline.end()) {
                    it->addLeading(comment);
                } else {
                    res.fileComments.push_back(comment);
                }
            }
        }

        return res;
    }

    struct MethodEntry {
        enum class Kind { Function, Inline } kind;

        broma::FunctionBindField* fn = nullptr;
        broma::InlineField* inl = nullptr;

        std::vector<broma::CommentField*> comments;
        broma::CommentField* trailingComment = nullptr;

        std::string name;
        size_t virtualIndex = SIZE_MAX;

        bool isCtor = false;
        bool isDtor = false;
        bool isStatic = false;
        bool isVirtual = false;

        [[nodiscard]] int sectionRank() const {
            if (isCtor)    return 0;
            if (isDtor)    return 1;
            if (isStatic)  return 2;
            if (isVirtual) return 3;
            return 4;
        }

        MethodEntry& withComments(std::vector<broma::CommentField*>& comm) {
            comments = comm;
            comm.clear();
            return *this;
        }

        static MethodEntry fromFunction(broma::FunctionBindField* fn, size_t vIndex) {
            return MethodEntry {
                .kind = Kind::Function,
                .fn = fn,
                .name = fn->prototype.name,
                .virtualIndex = vIndex,
                .isCtor = fn->prototype.type == broma::FunctionType::Ctor,
                .isDtor = fn->prototype.type == broma::FunctionType::Dtor,
                .isStatic = fn->prototype.is_static,
                .isVirtual = fn->prototype.is_virtual
            };
        }

        static MethodEntry fromInline(broma::InlineField* inl, std::string_view className) {
            std::string_view innerView(inl->inner);
            size_t parenPos = innerView.find('(');
            if (parenPos == std::string_view::npos) {
                parenPos = innerView.size();
            }

            size_t nameEnd = parenPos;
            size_t nameStart = innerView.rfind(' ', nameEnd - 1);
            if (nameStart == std::string_view::npos) {
                nameStart = 0;
            } else {
                nameStart += 1;
            }

            std::string name(innerView.substr(nameStart, nameEnd - nameStart));
            bool isCtor = name == className;
            bool isStatic = innerView.find("static") != std::string_view::npos;

            return MethodEntry {
                .kind = Kind::Inline,
                .inl = inl,
                .name = std::move(name),
                .virtualIndex = SIZE_MAX,
                .isCtor = isCtor,
                .isDtor = false,
                .isStatic = isStatic,
                .isVirtual = false
            };
        }
    };

    struct MemberEntry {
        enum class Kind { Padding, Field } kind;

        broma::MemberField* field = nullptr;
        broma::PadField* pad = nullptr;

        std::vector<broma::CommentField*> comments;
        broma::CommentField* trailingComment = nullptr;

        MemberEntry& withComments(std::vector<broma::CommentField*>& comm) {
            comments = comm;
            comm.clear();
            return *this;
        }

        static MemberEntry fromField(broma::MemberField* field) {
            return MemberEntry {
                .kind = Kind::Field,
                .field = field
            };
        }

        static MemberEntry fromPad(broma::PadField* pad) {
            return MemberEntry {
                .kind = Kind::Padding,
                .pad = pad
            };
        }
    };
}

static bool has(broma::Platform platform, broma::Platform check) {
    return (platform & check) == check;
}

template <>
struct fmt::formatter<broma::Platform> {
    constexpr auto parse(format_parse_context& ctx) { return ctx.begin(); }

    template <typename FormatContext>
    auto format(broma::Platform platform, FormatContext& ctx) const noexcept {
        if (platform == broma::Platform::None) {
            return ctx.out();
        }

        bool first = true;
        auto append = [&](std::string_view str) {
            if (!first) fmt::format_to(ctx.out(), ", ");
            fmt::format_to(ctx.out(), "{}", str);
            first = false;
        };

        if (has(platform, broma::Platform::Windows)) {
            append("win");
        }

        if (has(platform, broma::Platform::Android)) {
            append("android");
        } else if (has(platform, broma::Platform::Android64)) {
            append("android64");
        } else if (has(platform, broma::Platform::Android32)) {
            append("android32");
        }

        if (has(platform, broma::Platform::Mac)) {
            append("mac");
        } else if (has(platform, broma::Platform::MacIntel)) {
            append("imac");
        } else if (has(platform, broma::Platform::MacArm)) {
            append("m1");
        }

        if (has(platform, broma::Platform::iOS)) {
            append("ios");
        }

        return ctx.out();
    }
};

template <>
struct fmt::formatter<broma::Header> {
    constexpr auto parse(format_parse_context& ctx) { return ctx.begin(); }

    template <typename FormatContext>
    auto format(broma::Header const& header, FormatContext& ctx) const noexcept {
        if (header.platform == broma::Platform::All) {
            return fmt::format_to(ctx.out(), "#import <{}>", header.name);
        }
        return fmt::format_to(ctx.out(), "#import {} <{}>", header.platform, header.name);
    }
};

template <>
struct fmt::formatter<broma::Comment> {
    constexpr auto parse(format_parse_context& ctx) { return ctx.begin(); }

    template <typename FormatContext>
    auto format(broma::Comment const& comment, FormatContext& ctx) const noexcept {
        if (comment.multiline) {
            return fmt::format_to(ctx.out(), "/*{}*/", comment.inner);
        }
        return fmt::format_to(ctx.out(), "// {}", comment.inner);
    }
};

template <>
struct fmt::formatter<broma::CommentField> {
    constexpr auto parse(format_parse_context& ctx) { return ctx.begin(); }

    template <typename FormatContext>
    auto format(broma::CommentField const& comment, FormatContext& ctx) const noexcept {
        if (comment.multiline) {
            return fmt::format_to(ctx.out(), "/*{}*/", comment.inner);
        }
        return fmt::format_to(ctx.out(), "// {}", comment.inner);
    }
};

template <>
struct fmt::formatter<broma::Attributes> {
    size_t indentLevel = 0;

    constexpr auto parse(format_parse_context const& ctx) {
        auto it = ctx.begin();
        auto end = ctx.end();

        if (it != end && *it == 'I') {
            ++it;

            size_t numLen = 0;
            while (it != end && *it >= '0' && *it <= '9') {
                ++it;
                ++numLen;
            }

            if (numLen == 0) throw format_error("invalid format specifier");
            std::from_chars(ctx.begin() + 1, it, indentLevel);
        }

        if (it != end && *it != '}') {
            throw format_error("invalid format specifier");
        }

        return it;
    }

    template <typename FormatContext>
    auto format(broma::Attributes const& attr, FormatContext& ctx) const noexcept {
        // write docs
        if (!attr.docs.empty()) {
            size_t start = 0;
            while (start < attr.docs.size()) {
                size_t end = attr.docs.find('\n', start);
                if (end == std::string::npos)
                    end = attr.docs.size();

                std::string_view line(attr.docs.data() + start, end - start);

                auto firstIt = line.find_first_not_of(" \t");
                if (firstIt != std::string_view::npos) {
                    line.remove_prefix(firstIt);
                }

                auto lastIt = line.find_last_not_of(" \t\r");
                if (lastIt != std::string_view::npos) {
                    line.remove_suffix(line.size() - lastIt - 1);
                }

                if (!line.empty()) {
                    for (size_t i = 0; i < indentLevel; ++i) {
                        fmt::format_to(ctx.out(), "    ");
                    }
                    fmt::format_to(ctx.out(), "/// {}\n", line);
                }

                start = end == attr.docs.size() ? end : end + 1;
            }
        }

        bool hasAttrs =
            attr.links != broma::Platform::None ||
            attr.missing != broma::Platform::None ||
            !attr.depends.empty() ||
            !attr.since.empty() ||
            !attr.renamed_from.empty();

        if (!hasAttrs) {
            return ctx.out();
        }

        for (size_t i = 0; i < indentLevel; ++i) {
            fmt::format_to(ctx.out(), "    ");
        }

        fmt::format_to(ctx.out(), "[[");

        bool first = true;

        if (attr.links != broma::Platform::None) {
            if (!first) fmt::format_to(ctx.out(), ", ");
            fmt::format_to(ctx.out(), "link({})", attr.links);
            first = false;
        }

        if (attr.missing != broma::Platform::None) {
            if (!first) fmt::format_to(ctx.out(), ", ");
            fmt::format_to(ctx.out(), "missing({})", attr.missing);
            first = false;
        }

        if (!attr.depends.empty()) {
            if (!first) fmt::format_to(ctx.out(), ", ");
            fmt::format_to(ctx.out(), "depends({})", fmt::join(attr.depends, ", "));
            first = false;
        }

        if (!attr.since.empty()) {
            if (!first) fmt::format_to(ctx.out(), ", ");
            fmt::format_to(ctx.out(), "since(\"{}\")", attr.since);
            first = false;
        }

        if (!attr.renamed_from.empty()) {
            if (!first) fmt::format_to(ctx.out(), ", ");
            fmt::format_to(ctx.out(), "renamed_from({})", fmt::join(attr.renamed_from, ", "));
            first = false;
        }

        fmt::format_to(ctx.out(), "]]\n");

        return ctx.out();
    }
};

template <>
struct fmt::formatter<broma::MemberField> {
    constexpr auto parse(format_parse_context& ctx) { return ctx.begin(); }

    template <typename FormatContext>
    auto format(broma::MemberField const& member, FormatContext& ctx) const noexcept {
        fmt::format_to(ctx.out(), "{:I1}    ", member.attributes);

        if (member.platform != broma::Platform::All) {
            fmt::format_to(ctx.out(), "{} {{\n        ", member.platform);
        }

        fmt::format_to(ctx.out(), "{} {};", member.type.name, member.name);

        if (member.platform != broma::Platform::All) {
            fmt::format_to(ctx.out(), "\n    }}");
        }

        return ctx.out();
    }
};

template <>
struct fmt::formatter<broma::PlatformNumber> {
    constexpr auto parse(format_parse_context& ctx) { return ctx.begin(); }

    template <typename FormatContext>
    auto format(broma::PlatformNumber const& plat, FormatContext& ctx) const noexcept {
        constexpr ptrdiff_t PLATFORM_MISSING = -1;
        constexpr ptrdiff_t PLATFORM_INLINED = -2;

        if (
            plat.imac == PLATFORM_MISSING &&
            plat.m1 == PLATFORM_MISSING &&
            plat.ios == PLATFORM_MISSING &&
            plat.win == PLATFORM_MISSING &&
            plat.android32 == PLATFORM_MISSING &&
            plat.android64 == PLATFORM_MISSING
        ) {
            return ctx.out();
        }

        if (
            plat.imac == PLATFORM_INLINED &&
            plat.m1 == PLATFORM_INLINED &&
            plat.ios == PLATFORM_INLINED &&
            plat.win == PLATFORM_INLINED &&
            plat.android32 == PLATFORM_INLINED &&
            plat.android64 == PLATFORM_INLINED
        ) {
            return fmt::format_to(ctx.out(), " = inline");
        }

        size_t inlineCount = 0;
        if (plat.imac == PLATFORM_INLINED) ++inlineCount;
        if (plat.m1 == PLATFORM_INLINED) ++inlineCount;
        if (plat.ios == PLATFORM_INLINED) ++inlineCount;
        if (plat.win == PLATFORM_INLINED) ++inlineCount;
        if (plat.android32 == PLATFORM_INLINED) ++inlineCount;
        if (plat.android64 == PLATFORM_INLINED) ++inlineCount;

        bool first = true;
        auto append = [&](std::string_view str, ptrdiff_t value) {
            if (value == PLATFORM_MISSING) {
                return;
            }

            if (value == PLATFORM_INLINED) {
                if (inlineCount <= 2) {
                    if (!first) fmt::format_to(ctx.out(), ", ");
                    fmt::format_to(ctx.out(), "{} inline", str);
                    first = false;
                }
            } else {
                if (!first) fmt::format_to(ctx.out(), ", ");
                fmt::format_to(ctx.out(), "{} 0x{:x}", str, value);
                first = false;
            }
        };

        fmt::format_to(ctx.out(), " = ");

        append("win", plat.win);

        if (plat.android32 == plat.android64) {
            if (plat.android32 != PLATFORM_INLINED) {
                append("android", plat.android64);
            }
        } else {
            append("android64", plat.android64);
            append("android32", plat.android32);
        }

        if (plat.imac == plat.m1) {
            append("mac", plat.imac);
        } else {
            append("imac", plat.imac);
            append("m1", plat.m1);
        }

        append("ios", plat.ios);

        if (inlineCount > 2) {
            if (!first) fmt::format_to(ctx.out(), ", inline", inlineCount);
            else fmt::format_to(ctx.out(), "inline", inlineCount);
        }

        return ctx.out();
    }
};

template <>
struct fmt::formatter<broma::PadField> {
    constexpr auto parse(format_parse_context& ctx) { return ctx.begin(); }

    template <typename FormatContext>
    auto format(broma::PadField const& pad, FormatContext& ctx) const noexcept {
        return fmt::format_to(ctx.out(), "PAD{};", pad.amount);
    }
};


template <>
struct fmt::formatter<broma::AccessModifier> {
    constexpr auto parse(format_parse_context const& ctx) { return ctx.begin(); }

    template <typename FormatContext>
    auto format(broma::AccessModifier const& access, FormatContext& ctx) const noexcept {
        switch (access) {
            case broma::AccessModifier::Public:
                return fmt::format_to(ctx.out(), "public");
            case broma::AccessModifier::Protected:
                return fmt::format_to(ctx.out(), "protected");
            case broma::AccessModifier::Private:
                return fmt::format_to(ctx.out(), "private");
            default:
                return fmt::format_to(ctx.out(), "unknown");
        }
    }
};

namespace bromascan {
    struct LexicographicalComparer {
        constexpr bool operator()(std::string_view a, std::string_view b) const noexcept {
            return std::ranges::lexicographical_compare(a, b,
                [](char ac, char bc) {
                    return std::tolower(ac) < std::tolower(bc);
                }
            );
        }
    };

    template <size_t Capacity>
    struct StringBuffer {
        fmt::basic_memory_buffer<char, Capacity> buffer;

        void append(std::string_view str) {
            fmt::format_to(std::back_inserter(buffer), "{}", str);
        }

        template <typename... Args>
        void append(fmt::format_string<Args...> fmtStr, Args&&... args) {
            fmt::format_to(std::back_inserter(buffer), fmtStr, std::forward<Args>(args)...);
        }

        [[nodiscard]] size_t size() const {
            return buffer.size();
        }

        [[nodiscard]] std::string str() const {
            return fmt::to_string(buffer);
        }
    };

    Result<std::string> formatBromaFile(broma::Root const& root) {
        auto const& [classes, functions, headers, comments] = root;

        fmt::println(
            "Writing Broma file with {} headers, {} classes, {} functions, and {} comments",
            headers.size(), classes.size(), functions.size(), comments.size()
        );

        constexpr size_t MEMORY_BUFFER_SIZE = 1024 * 1024; // 1 MB
        StringBuffer<MEMORY_BUFFER_SIZE> buffer;

        buffer.append("{}", fmt::join(headers, "\n"));

        if (!headers.empty()) {
            buffer.append("\n\n");
        }

        auto ast = attachComments(root);

        std::ranges::sort(ast.classes, [](auto const& a, auto const& b) {
            return LexicographicalComparer{}(a.cls.name, b.cls.name);
        });

        for (auto& cls : ast.classes) {
            if (!cls.leadingComments.empty()) {
                buffer.append("{}\n", fmt::join(cls.leadingComments, "\n"));
            }

            auto& depends = cls.cls.attributes.depends;
            std::erase_if(depends, [&](std::string const& dep) {
                return std::ranges::find(cls.cls.superclasses, dep) != cls.cls.superclasses.end();
            });

            buffer.append("{}", cls.cls.attributes);

            if (cls.cls.superclasses.empty()) {
                buffer.append("class {} {{", cls.cls.name);
            } else {
                buffer.append("class {} : {} {{", cls.cls.name, fmt::join(cls.cls.superclasses, ", "));
            }

            std::vector<MethodEntry> entries;
            std::vector<MemberEntry> members;
            std::vector<broma::CommentField*> pendingComments;
            std::vector<broma::CommentField*> classComments;
            entries.reserve(cls.cls.fields.size());
            members.reserve(cls.cls.fields.size());
            bool hasMembers = false;

            bool lastWasMethod = true;

            size_t virtualCounter = 0;
            bool topLevelComment = true;
            bool hadTopLevelComment = false;

            for (auto& field : cls.cls.fields) {
                if (auto fn = field.get_as<broma::FunctionBindField>()) {
                    topLevelComment = false;
                    entries.emplace_back(
                        MethodEntry::fromFunction(fn, virtualCounter)
                            .withComments(pendingComments)
                    );
                    if (fn->prototype.is_virtual) {
                        virtualCounter++;
                    }
                    lastWasMethod = true;
                } else if (auto inl = field.get_as<broma::InlineField>()) {
                    topLevelComment = false;
                    entries.emplace_back(
                        MethodEntry::fromInline(inl, cls.cls.name)
                            .withComments(pendingComments)
                    );
                    lastWasMethod = true;
                } else if (auto comment = field.get_as<broma::CommentField>()) {
                    if (comment->trailing) {
                        // attach to last member if possible
                        if (lastWasMethod && !entries.empty()) {
                            entries.back().trailingComment = comment;
                        } else if (!lastWasMethod && !members.empty()) {
                            members.back().trailingComment = comment;
                        }

                        continue;
                    }

                    if (topLevelComment) {
                        hadTopLevelComment = true;

                        bool isCtorDtor = comment->inner.contains('~') || comment->inner.contains('(');
                        if (isCtorDtor) {
                            classComments.push_back(comment);
                        } else {
                            pendingComments.push_back(comment);
                        }
                    } else {
                        pendingComments.push_back(comment);
                    }
                    continue;
                } else if (auto member = field.get_as<broma::MemberField>()) {
                    topLevelComment = false;
                    hasMembers = true;
                    members.emplace_back(
                        MemberEntry::fromField(member)
                            .withComments(pendingComments)
                    );
                    lastWasMethod = false;
                } else if (auto pad = field.get_as<broma::PadField>()) {
                    topLevelComment = false;
                    hasMembers = true;
                    members.emplace_back(
                        MemberEntry::fromPad(pad)
                            .withComments(pendingComments)
                    );
                    lastWasMethod = false;
                }

                topLevelComment = false;
            }

            // sort methods
            std::ranges::sort(entries, [](auto const& a, auto const& b) {
                if (a.sectionRank() != b.sectionRank()) {
                    return a.sectionRank() < b.sectionRank();
                }
                if (a.isVirtual && b.isVirtual) {
                    return a.virtualIndex < b.virtualIndex;
                }

                // for overloads, sort by arguments
                if (a.name == b.name) {
                    if (a.kind == MethodEntry::Kind::Function && b.kind == MethodEntry::Kind::Function) {
                        auto& aArgs = a.fn->prototype.args;
                        auto& bArgs = b.fn->prototype.args;
                        if (aArgs.size() != bArgs.size()) {
                            return aArgs.size() < bArgs.size();
                        }
                        for (size_t i = 0; i < aArgs.size(); ++i) {
                            if (aArgs[i].first.name != bArgs[i].first.name) {
                                return aArgs[i].first.name < bArgs[i].first.name;
                            }
                        }
                    }
                }

                // return a.name < b.name;
                return LexicographicalComparer{}(a.name, b.name);
            });


            bool hasCtor = false;
            bool hasDtor = false;
            for (auto const& entry : entries) {
                if (entry.isCtor) {
                    hasCtor = true;
                } else if (entry.isDtor) {
                    hasDtor = true;
                }

                if (hasCtor && hasDtor) {
                    break;
                }
            }

            // write methods
            enum class LastSection { Ctor, Static, Virtual, Normal } lastSection = LastSection::Normal;

            if (!entries.empty()) {
                auto& firstEntry = *entries.begin();
                lastSection = !classComments.empty() || firstEntry.isCtor || firstEntry.isDtor ? LastSection::Ctor :
                              firstEntry.isStatic  ? LastSection::Static :
                              firstEntry.isVirtual ? LastSection::Virtual :
                                                     LastSection::Normal;
            }

            if (!cls.cls.fields.empty()) {
                buffer.append("\n");

                for (auto* comment : classComments) {
                    buffer.append("    {}\n", *comment);
                }

                for (auto const& entry : entries) {
                    bool switchedSection = false;

                    // separate different types of methods with a newline
                    if (entry.isCtor || entry.isDtor) {
                        if (lastSection != LastSection::Ctor) {
                            buffer.append("\n");
                            lastSection = LastSection::Ctor;
                            switchedSection = true;
                        }
                    } else if (entry.isStatic) {
                        if (lastSection != LastSection::Static) {
                            buffer.append("\n");
                            lastSection = LastSection::Static;
                            switchedSection = true;
                        }
                    } else if (entry.isVirtual) {
                        if (lastSection != LastSection::Virtual) {
                            buffer.append("\n");
                            lastSection = LastSection::Virtual;
                            switchedSection = true;
                        }
                    } else {
                        if (lastSection != LastSection::Normal) {
                            buffer.append("\n");
                            lastSection = LastSection::Normal;
                            switchedSection = true;
                        }
                    }

                    if (entry.kind == MethodEntry::Kind::Function) {
                        auto* method = &entry.fn->prototype;

                        // write comment
                        for (auto* comment : entry.comments) {
                            buffer.append("    {}\n", *comment);
                        }

                        // blank line if has docs
                        if (!switchedSection && !method->attributes.docs.empty()) {
                            buffer.append("\n");
                        }

                        // attributes
                        method->attributes.links &= ~cls.cls.attributes.links;
                        method->attributes.missing &= ~cls.cls.attributes.missing;

                        buffer.append("{:I1}    ", method->attributes);

                        // access specifier
                        if (method->access != broma::AccessModifier::Public) {
                            buffer.append("{} ", method->access);
                        }

                        // if callback
                        if (method->is_callback) {
                            buffer.append("callback ");
                        }

                        // declaration
                        if (method->is_static) {
                            buffer.append("static ");
                        } else if (method->is_virtual) {
                            buffer.append("virtual ");
                        }

                        if (method->type != broma::FunctionType::Normal) {
                            buffer.append("{}(", method->name);
                        } else {
                            buffer.append("{} {}(", method->ret.name, method->name);
                        }

                        bool shouldKeepDefaultNames = entry.fn->inner.contains("p0");

                        // args
                        for (size_t i = 0; i < method->args.size(); ++i) {
                            auto const& [argType, argName] = method->args[i];
                            // if argName follows `p0`, `p1`, etc., we can omit it
                            if (!shouldKeepDefaultNames && argName == fmt::format("p{}", i)) {
                                buffer.append("{}", argType.name);
                            } else {
                                buffer.append("{} {}", argType.name, argName);
                            }
                            if (i + 1 < method->args.size()) {
                                buffer.append(", ");
                            }
                        }

                        if (method->is_variadic) {
                            if (!method->args.empty()) {
                                buffer.append(", ");
                            }
                            buffer.append("...");
                        }

                        buffer.append(")");

                        // const qualifier
                        if (method->is_const) {
                            buffer.append(" const");
                        }

                        // bindings
                        buffer.append("{}", entry.fn->binds);
                        if (!entry.fn->inner.empty()) {
                            buffer.append(" {}", entry.fn->inner);
                        } else {
                            buffer.append(";");
                        }
                    } else if (entry.kind == MethodEntry::Kind::Inline) {
                        // write inline field directly
                        buffer.append("    {}", entry.inl->inner);
                    }

                    if (entry.trailingComment) {
                        buffer.append(" {}", *entry.trailingComment);
                    }

                    buffer.append("\n");
                }

                if (hasMembers && (!entries.empty() || hadTopLevelComment)) {
                    buffer.append("\n");
                }

                for (auto const& member : members) {
                    for (auto* comment : member.comments) {
                        buffer.append("    {}\n", *comment);
                    }

                    if (member.kind == MemberEntry::Kind::Field) {
                        buffer.append("{}", *member.field);
                    } else if (member.kind == MemberEntry::Kind::Padding) {
                        buffer.append("    {}", *member.pad);
                    }

                    if (member.trailingComment) {
                        buffer.append(" {}\n", *member.trailingComment);
                    } else {
                        buffer.append("\n");
                    }
                }
            }

            buffer.append("}");

            if (!cls.trailingComments.empty()) {
                buffer.append(" {}\n", fmt::join(cls.trailingComments, " "));
            } else {
                buffer.append("\n\n");
            }
        }

        // for (auto& fn : functions) {
        //     auto* method = &fn.prototype;
        //
        //     // blank line if has docs
        //     if (!method->attributes.docs.empty()) {
        //         fmt::println(file, "");
        //     }
        //
        //     // attributes
        //     auto attrs = formatAttributes(method->attributes, {});
        //     if (!attrs.empty()) {
        //         fmt::print(file, "{}", attrs);
        //     }
        //
        //     fmt::print(file, "{} {}(", method->ret.name, method->name);
        //
        //     // args
        //     bool shouldKeepDefaultNames = fn.inner.contains("p0");
        //     for (size_t i = 0; i < method->args.size(); ++i) {
        //         auto const& [argType, argName] = method->args[i];
        //
        //         // if argName follows `p0`, `p1`, etc., we can omit it
        //         if (!shouldKeepDefaultNames && argName == fmt::format("p{}", i)) {
        //             fmt::print(file, "{}", argType.name);
        //         } else {
        //             fmt::print(file, "{} {}", argType.name, argName);
        //         }
        //
        //         if (i + 1 < method->args.size()) {
        //             fmt::print(file, ", ");
        //         }
        //     }
        //
        //     fmt::print(file, ")");
        //
        //     // bindings
        //     auto bindStr = fmt::to_string(fn.binds);
        //     fmt::print(file, "{}", bindStr);
        //     if (!fn.inner.empty()) {
        //         fmt::print(file, " {}", fn.inner);
        //     } else {
        //         fmt::print(file, ";");
        //     }
        //
        //     fmt::print(file, "\n");
        // }

        return Ok(buffer.str());
    }
}
