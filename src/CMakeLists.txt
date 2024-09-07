project(ip_filter_lib)
add_library(${PROJECT_NAME}
        ip_filter.cpp
)

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/include)

