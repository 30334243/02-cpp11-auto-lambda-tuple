add_executable(ip_filter_test
        test_main.cpp
        test_ip_filter.cpp
)

target_link_libraries(ip_filter_test
        PRIVATE
        Boost::boost
        GTest::gtest
        GTest::gtest_main
        ${PROJECT_NAME}_lib
)