#include <gtest/gtest.h>
#include "ip_filter.h"
#include "otus_tasks.h"

// Функция для запуска команды и получения её вывода
std::string exec(const char *cmd) {
    char buffer[128]{};
    std::string result{};
    FILE *pipe{popen(cmd, "r")};
    if (!pipe) throw std::runtime_error("popen() failed!");
    try {
        while (fgets(buffer, sizeof buffer, pipe) != nullptr) {
            result += buffer;
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    pclose(pipe);
    return result;
}

//-------------------TESTS-------------------

TEST(test_ip_filter, ip_parsing) {
    static constexpr int kEthalonSizeIPs{2};
    static std::string const kEthalonIP{
        "255.255.255.255"
    };
    static std::vector<std::string> const in{
        "255.255.255.255\t",
        "255.255.255.255.255\t",
        "2555.255.255.255\t",
        "255.2555.255.255\t",
        "255.255.2555.255\t",
        "255.255.255.2555\t",
        "255.255.255\t",
        "255.255.255.255",
    };
    IpFilter ip_filter{};
    ASSERT_NO_THROW(ip_filter.ParsingInputVector(in));
    auto const ips{ip_filter.GetIPs()};
    ASSERT_EQ(ips.size(), kEthalonSizeIPs);
    for (auto const &ip: ips) {
        ASSERT_TRUE(std::ranges::equal(ip.to_string(), kEthalonIP));
    }
}

TEST(test_ip_filter, ip_sorting) {
    static std::vector<std::string> const kEthalonIP{
        "255.255.255.255",
        "128.128.128.128",
        "1.1.1.1"
    };
    static std::vector<std::string> const in{
        "128.128.128.128\t",
        "255.255.255.255\t",
        "1.1.1.1\t"
    };
    IpFilter ip_filter{};
    ASSERT_NO_THROW(ip_filter.ParsingInputVector(in));
    ip_filter.Sorting(std::greater{});
    auto const ips{ip_filter.GetIPs()};
    ASSERT_EQ(ips.size(), kEthalonIP.size());
    for (int i{}; i < ips.size(); ++i) {
        ASSERT_TRUE(std::ranges::equal(ips[i].to_string(), kEthalonIP[i]));
    }
}

TEST(test_ip_filter, otus_task) {
    std::string const cmd{"cd .. && cat ip_filter.tsv | ./ip_filter | md5sum"};
    std::string const output{exec(cmd.c_str())};
    std::string const ethalon{"24e7a7b2270daee89c64d3ca5fb3da1a  -\n"};
    EXPECT_EQ(output, ethalon);
}
