#include <fstream>
#include <ranges>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include "ip_filter.h"
#include "version.h"

IpFilter::IpFilter(std::string const file) : file{file} {
}

uint64_t IpFilter::Version() {
    return PROJECT_VERSION_PATCH;
}

bool IpFilter::ParsingInputFile() {
    bool ret{};
    if (std::ifstream src{file}; !src.fail()) {
        std::string line{};
        while (std::getline(src, line)) {
            parsing(line);
        }
        ret = true;
    }
    return ret;
}

void IpFilter::parsing(std::string const &line) {
    for (auto const &ip: std::views::split(line, '\t') |
                         std::views::take(1) |
                         std::views::filter(is_valid_size) |
                         std::views::transform(convert_to_ip) |
                         std::views::filter(is_valid_ip) |
                         std::views::transform(get_ip)) {
        ips.emplace_back(ip);
    }
}

void IpFilter::ParsingInputVector(std::vector<std::string> const &in) {
    for (auto const& line : in) {
        parsing(line);
    }
}

void IpFilter::Sorting(
    std::function<bool(boost::asio::ip::address_v4 const &, boost::asio::ip::address_v4 const &)> func) {
    std::ranges::sort(ips, func);
}

std::vector<boost::asio::ip::address_v4> IpFilter::GetIPs() const {
    return ips;
}