find_package(GTest REQUIRED)

add_executable(${PROJECT_NAME}_test
        test_main.cpp
        test_ip_filter.cpp
)

target_link_libraries(${PROJECT_NAME}_test
        PRIVATE
        Boost::system
        Boost::filesystem
        GTest::gtest
        GTest::gtest_main
        ip_filter_lib
)

add_test(NAME ${PROJECT_NAME}_test COMMAND ${PROJECT_NAME}_test)
gtest_discover_tests(${PROJECT_NAME}_test)

set(TEST_FILES
        ${CMAKE_SOURCE_DIR}/tests/files/ip_filter.tsv
)

add_custom_command(TARGET ${PROJECT_NAME}_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy ${TEST_FILES} ${CMAKE_BINARY_DIR}/tests
        COMMENT "Copying test files to output directory"
)