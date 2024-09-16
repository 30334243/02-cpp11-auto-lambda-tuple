add_library(${PROJECT_NAME}_lib
        ip_filter.cpp
)

target_include_directories(${PROJECT_NAME}_lib PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(${PROJECT_NAME}_lib PRIVATE Boost::system Boost::filesystem)
