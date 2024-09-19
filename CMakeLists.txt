cmake_minimum_required(VERSION 3.22)

if (WINDOWS_SPECIFIC_FLAG)
    include(${ENV})
endif ()

set(PROJECT_VERSION_PATCH $ENV{GITHUB_RUN_NUMBER})

if (NOT DEFINED PROJECT_VERSION_PATCH OR PROJECT_VERSION_PATCH STREQUAL "")
    set(PROJECT_VERSION_PATCH 1)
endif ()

set(PATCH_VERSION "${PROJECT_VERSION_PATCH}" CACHE INTERNAL "Patch version")
set(PROJECT_VERSION 0.0.${PATCH_VERSION})

project(ip_filter VERSION ${PROJECT_VERSION})
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif ()
add_definitions(-D_WIN32_WINNT=0x0601)

if (WINDOWS_SPECIFIC_FLAG)
    find_package(Boost 1.86 REQUIRED COMPONENTS system filesystem)
else ()
    find_package(Boost REQUIRED COMPONENTS system filesystem)
endif ()

configure_file(version.h.in version.h)

add_subdirectory(src)

add_executable(${PROJECT_NAME} main.cpp)

target_include_directories(${PROJECT_NAME}_lib
        PUBLIC ${CMAKE_BINARY_DIR}
)

target_link_libraries(${PROJECT_NAME} PRIVATE ${PROJECT_NAME}_lib Boost::system)

enable_testing()
add_subdirectory(tests)

if (WINDOWS_SPECIFIC_FLAG)
    target_compile_options(${PROJECT_NAME} PRIVATE
            /W4
    )
    target_compile_options(${PROJECT_NAME}_lib PRIVATE
            /W4
    )
    target_compile_options(${PROJECT_NAME}_test PRIVATE
            /W4
    )
elseif (WSL_SPECIFIC_FLAG)
        target_compile_options(${PROJECT_NAME} PRIVATE
                -Wall -Wextra -pedantic -Werror
        )
        target_compile_options(${PROJECT_NAME}_lib PRIVATE
                -Wall -Wextra -pedantic -Werror
        )
        target_compile_options(${PROJECT_NAME}_test PRIVATE
                -Wall -Wextra -pedantic -Werror
        )
else ()
    message(FATAL_ERROR "Error. Stopping. Unknown Platform")
endif ()

set(TEST_FILES
        ${CMAKE_SOURCE_DIR}/tests/files/ip_filter.tsv
)

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy ${TEST_FILES} $<TARGET_FILE_DIR:${PROJECT_NAME}>
        COMMENT "Copying test files to output directory"
)


install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)

set(CPACK_GENERATOR DEB)
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(CPACK_PACKAGE_CONTACT fabish@bk.ru)
include(CPack)
