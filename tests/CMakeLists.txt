project(ip_filter)
add_executable(${PROJECT_NAME}_test
        test_main.cpp
        test_ip_filter.cpp
)


target_link_libraries(${PROJECT_NAME}_test
        PRIVATE
        GTest::gtest
        GTest::gtest_main
        ${PROJECT_NAME}_lib
)