cmake_minimum_required(VERSION 3.22)

if (NOT DEFINED PROJECT_VERSION_PATCH OR PROJECT_VERSION_PATCH STREQUAL "")
    set(PROJECT_VERSION_PATCH 1)
endif ()

set(PATCH_VERSION "${PROJECT_VERSION_PATCH}" CACHE INTERNAL "Patch version")
set(PROJECT_VERSION 0.0.${PATCH_VERSION})

project(ip_filter VERSION ${PROJECT_VERSION})
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(GTest REQUIRED)
find_package(Boost REQUIRED)

enable_testing()

configure_file(version.h.in version.h)

add_subdirectory(src)
add_subdirectory(tests)

add_executable(${PROJECT_NAME} main.cpp include/otus_tasks.h)

target_include_directories(${PROJECT_NAME}_lib
        PUBLIC ${CMAKE_BINARY_DIR}
)

target_link_libraries(${PROJECT_NAME} PRIVATE ${PROJECT_NAME}_lib)

#target_compile_options(${PROJECT_NAME} PRIVATE
#        -Wall -Wextra -pedantic -Werror
#)
#target_compile_options(${PROJECT_NAME}_lib PRIVATE
#        -Wall -Wextra -pedantic -Werror
#)
#target_compile_options(${PROJECT_NAME}_test PRIVATE
#        -Wall -Wextra -pedantic -Werror
#)

set(TEST_FILES
        ${CMAKE_SOURCE_DIR}/tests/files/ip_filter.tsv
)

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy ${TEST_FILES} $<TARGET_FILE_DIR:${PROJECT_NAME}>
        COMMAND ${CMAKE_COMMAND} -E copy ${TEST_FILES} $<TARGET_FILE_DIR:${PROJECT_NAME}>/tests
        COMMENT "Copying test files to output directory"
)

install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)

set(CPACK_GENERATOR DEB)
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(CPACK_PACKAGE_CONTACT fabish@bk.ru)
include(CPack)
