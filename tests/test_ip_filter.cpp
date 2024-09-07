#include <gtest/gtest.h>
#include "ip_filter.h"

TEST(SomeClassTest, TestName) {
    IpFilter ip_filter{};
    ASSERT_GT(ip_filter.Version(), 0);
}