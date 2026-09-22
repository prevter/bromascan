cmake_minimum_required(VERSION 3.21)
project(bromascan VERSION 1.0.0 LANGUAGES CXX)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU|AppleClang")
    add_compile_options(-march=native)
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    add_compile_options(/arch:AVX2)
endif()

include(cmake/CPM.cmake)

CPMAddPackage("gh:fmtlib/fmt#12.2.0")
CPMAddPackage("gh:prevter/sinaps#b9c3434")
CPMAddPackage("gh:jarro2783/cxxopts@3.3.1")
CPMAddPackage("gh:geode-sdk/result@1.4.1")
CPMAddPackage("gh:nlohmann/json@3.12.0")
CPMAddPackage("gh:prevter/Broma#d09f8ac")

# capstone for aarch64
CPMAddPackage(
    NAME Capstone
    GITHUB_REPOSITORY capstone-engine/capstone
    GIT_TAG 6.0.0-Alpha5
    OPTIONS
        "CAPSTONE_BUILD_STATIC ON"
        "CAPSTONE_BUILD_SHARED OFF"
        "CAPSTONE_BUILD_TESTS OFF"
        "CAPSTONE_BUILD_DIET OFF"
        "CAPSTONE_BUILD_CSTOOL OFF"
        "CAPSTONE_X86_SUPPORT OFF"
        "CAPSTONE_PPC_SUPPORT OFF"
        "CAPSTONE_MIPS_SUPPORT OFF"
        "CAPSTONE_SPARC_SUPPORT OFF"
        "CAPSTONE_SYSTEMZ_SUPPORT OFF"
        "CAPSTONE_XCORE_SUPPORT OFF"
        "CAPSTONE_M68K_SUPPORT OFF"
        "CAPSTONE_TMS320C64X_SUPPORT OFF"
        "CAPSTONE_EVM_SUPPORT OFF"
        "CAPSTONE_M680X_SUPPORT OFF"
        "CAPSTONE_ARM_SUPPORT ON"
        "CAPSTONE_AARCH64_SUPPORT ON"
)

# zydis for amd64
CPMAddPackage(
    NAME Zydis
    GITHUB_REPOSITORY zyantific/zydis
    VERSION 4.1.1
    OPTIONS
        "ZYDIS_FEATURE_ENCODER OFF"
        "ZYDIS_FEATURE_AVX512 OFF"
)

file(GLOB_RECURSE SOURCE_FILES CONFIGURE_DEPENDS shared/*.cpp)
add_library(${PROJECT_NAME} STATIC ${SOURCE_FILES})
target_include_directories(${PROJECT_NAME} PUBLIC shared)
target_link_libraries(${PROJECT_NAME} PUBLIC fmt::fmt sinaps cxxopts GeodeResult nlohmann_json::nlohmann_json Broma)

file(GLOB_RECURSE GENPAT_SOURCE_FILES CONFIGURE_DEPENDS genpat/*.cpp)
add_executable(genpat ${GENPAT_SOURCE_FILES})
target_link_libraries(genpat PRIVATE ${PROJECT_NAME} capstone_static Zydis)
target_compile_definitions(genpat PRIVATE GENPAT_VERSION="${PROJECT_VERSION}")

file(GLOB_RECURSE SCANPAT_SOURCE_FILES CONFIGURE_DEPENDS scanpat/*.cpp)
add_executable(scanpat ${SCANPAT_SOURCE_FILES})
target_link_libraries(scanpat PRIVATE ${PROJECT_NAME})
target_compile_definitions(scanpat PRIVATE SCANPAT_VERSION="${PROJECT_VERSION}")

file(GLOB_RECURSE BROUTIL_SOURCE_FILES CONFIGURE_DEPENDS broutil/*.cpp)
add_executable(broutil ${BROUTIL_SOURCE_FILES})
target_link_libraries(broutil PRIVATE ${PROJECT_NAME})
target_compile_definitions(broutil PRIVATE BROUTIL_VERSION="${PROJECT_VERSION}")