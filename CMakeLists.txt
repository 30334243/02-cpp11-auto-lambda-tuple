cmake_minimum_required(VERSION 3.22)

if (NOT DEFINED PROJECT_VERSION_PATCH OR PROJECT_VERSION_PATCH STREQUAL "")
    set(PROJECT_VERSION_PATCH 1)
endif ()

set(PATCH_VERSION "${PROJECT_VERSION_PATCH}" CACHE INTERNAL "Patch version")
set(PROJECT_VERSION 0.0.${PATCH_VERSION})

project(ip_filter VERSION ${PROJECT_VERSION})
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.14.0
)
FetchContent_MakeAvailable(googletest)

enable_testing()

configure_file(version.h.in version.h)

add_subdirectory(src)
add_subdirectory(tests)

add_executable(${PROJECT_NAME} main.cpp)

target_include_directories(${PROJECT_NAME}_lib
        PRIVATE ${CMAKE_BINARY_DIR}
)

target_link_libraries(${PROJECT_NAME} PRIVATE ${PROJECT_NAME}_lib)

target_compile_options(${PROJECT_NAME} PRIVATE
        -Wall -Wextra -pedantic -Werror
)
target_compile_options(${PROJECT_NAME}_lib PRIVATE
        -Wall -Wextra -pedantic -Werror
)
target_compile_options(${PROJECT_NAME}_test PRIVATE
        -Wall -Wextra -pedantic -Werror
)

install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)

set(CPACK_GENERATOR DEB)
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(CPACK_PACKAGE_CONTACT fabish@bk.ru)
include(CPack)
