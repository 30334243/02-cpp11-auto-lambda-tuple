add_library(ip_filter_lib
        ip_filter.cpp
)

target_include_directories(ip_filter_lib PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(ip_filter_lib PRIVATE Boost::boost)
