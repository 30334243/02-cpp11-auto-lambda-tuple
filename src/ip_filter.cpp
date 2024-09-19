#include <numeric>
#include <string>
#include <vector>
#include <tuple>
#include <sstream>
#include "ip_filter.h"

bool isAllDigits(const std::string &str) {
    for (char ch: str) {
        if (!std::isdigit(ch)) {
            return false;
        }
    }
    return true;
}

std::vector<std::string> splitString(const std::string &str, char delimiter) {
    std::vector<std::string> tokens;
    std::istringstream iss(str);
    std::string token;

    while (std::getline(iss, token, delimiter)) {
        if (isAllDigits(token)) {
            tokens.push_back(token);
        }
    }

    return tokens;
}

void IpFilter::parsing_cxx17(std::string const &in) {
    static constexpr int kMaxSizeIpString{16};
    static constexpr int kNumIpElements{4};

    if (auto const beg_tab{std::find(in.cbegin(), in.cend(), '\t')}; beg_tab != in.cend()) {
        size_t const len_ip_str{static_cast<size_t>(std::distance(in.cbegin(), beg_tab))};
        if (kMaxSizeIpString < len_ip_str) {
        } else if (auto const ip_elements{splitString(in.substr(0, len_ip_str), '.')};
            kNumIpElements != ip_elements.size()) {
        } else {
            ips_cxx17.emplace_back(parsingIpElements(ip_elements));
        }
    }
}

std::tuple<std::string, uint32_t> IpFilter::parsingIpElements(std::vector<std::string> const &ip_elements) {
    static constexpr int kStep{8};
    static constexpr int kMaxNumPoint{3};

    std::string ip_str{};
    uint32_t ip_addr{};
    for (size_t i{}, shift{24}; i < ip_elements.size(); ++i, shift -= kStep) {
        auto const &elm{ip_elements[i]};
        if (i < kMaxNumPoint) {
            ip_str.append(elm + '.');
        } else {
            ip_str.append(elm);
        }
        ip_addr |= std::stol(elm) << shift;
    }
    return std::make_tuple(ip_str, ip_addr);
}

IpFilter::IpFilter(std::string const &file) : file{file} {
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
                         std::views::filter(is_valid_num_points) | // for windows
                         std::views::transform(convert_to_ip) |
                         std::views::filter(is_valid_ip) |
                         std::views::transform(get_ip)) {
        ips.emplace_back(ip);
    }
}

void IpFilter::ParsingInputVector(std::vector<std::string> const &in) {
    for (auto const &line: in) {
        parsing(line);
    }
}

void IpFilter::Sorting(
    std::function<bool(boost::asio::ip::address_v4 const &, boost::asio::ip::address_v4 const &)> func) {
    std::ranges::sort(ips, func);
}

void IpFilter::filter_task_1() const {
    for (auto const &[str,_]: ips_cxx17) {
        std::cout << str << '\n';
    }
}

void IpFilter::filter_task_2() const {
    static constexpr int kFirstByte{3};

    for (auto const &[str,addr]: ips_cxx17) {
        uint8_t const* raw{reinterpret_cast<uint8_t const*>(&addr)};
        if (raw[kFirstByte] == 1) {
            std::cout << str << '\n';
        }
    }
}

void IpFilter::filter_task_3() const {
    static constexpr int kFirstByte{3};
    static constexpr int kSecondByte{2};

    for (auto const &[str,addr]: ips_cxx17) {
        uint8_t const* raw{reinterpret_cast<uint8_t const*>(&addr)};
        if (raw[kFirstByte] == 46 && raw[kSecondByte] == 70) {
            std::cout << str << '\n';
        }
    }
}

void IpFilter::filter_task_4() const {
    for (auto const &[str,addr]: ips_cxx17) {
        uint8_t const* raw{reinterpret_cast<uint8_t const*>(&addr)};
        if (std::find(raw, raw + 4, 46) != (raw + 4)) {
            std::cout << str << '\n';
        }
    }
}

bool IpFilter::ParsingCxx17() {
    bool ret{};
    if (std::ifstream src{file}; !src.fail()) {
        std::string line{};
        while (std::getline(src, line)) {
            parsing_cxx17(line);
        }
        std::sort(ips_cxx17.begin(), ips_cxx17.end(), [](auto &lhs, auto &rhs) {
            auto [_1,addr1]{lhs};
            auto [_2,addr2]{rhs};
            return addr2 < addr1;
        });
        filter_task_1();
        filter_task_2();
        filter_task_3();
        filter_task_4();
        ret = true;
    }
    return ret;
}

std::vector<boost::asio::ip::address_v4> IpFilter::GetIPs() const {
    return ips;
}
