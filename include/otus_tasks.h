#pragma once

#include <span>
#include <boost/asio/ip/address_v4.hpp>

namespace Otus {
static bool task_1(boost::asio::ip::address_v4 const &) {
    return true;
}

static constexpr auto task_2{
    [](boost::asio::ip::address_v4 const &ip) {
        static constexpr int kFirstByte{3};

        auto const raw_ip{ip.to_uint()};
        uint8_t const* raw{reinterpret_cast<uint8_t const*>(&raw_ip)};
        std::span<uint8_t const> const ptr_raw_ip{raw, sizeof(uint32_t)};
        return ptr_raw_ip[kFirstByte] == 1;
    }
};

static constexpr auto task_3{
    [](boost::asio::ip::address_v4 const &ip) {
        static constexpr int kFirstByte{3};
        static constexpr int kSecondByte{2};

        auto raw_ip{ip.to_uint()};
        uint8_t const * raw{reinterpret_cast<uint8_t const *>(&raw_ip)};
        std::span<uint8_t const> const ptr_raw_ip{raw, sizeof(uint32_t)};
        return ptr_raw_ip[kFirstByte] == 46 && ptr_raw_ip[kSecondByte] == 70;
    }
};

static constexpr auto task_4{
    [](boost::asio::ip::address_v4 const &ip) {
        auto raw_ip{ip.to_uint()};
        uint8_t const * raw{reinterpret_cast<uint8_t const *>(&raw_ip)};
        std::span<uint8_t const> const ptr_raw_ip{raw, sizeof(uint32_t)};
        return std::ranges::find(ptr_raw_ip, 46) != ptr_raw_ip.end();
    }
};
}