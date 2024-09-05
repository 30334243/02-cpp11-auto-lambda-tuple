#define GTEST_TEST_MODULE test_version

#include "lib.h"

#include <gtest/gtest.h>

TEST(TestSuiteName, TestName) {
	EXPECT_GT(version(), 0);
}

int main(int argc, char **argv) {
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
