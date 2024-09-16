#pragma once

#include <format>
#include <ranges>
#include <vector>
#include <iostream>
#include <boost/asio/ip/address_v4.hpp>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include "version.h"

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

/**
 * @brief Класс только для наследования. Функции для std::ranges
 */
class RangesFuncs {
protected:
    /// Тип данных. Информация об ip адресе после конвретации из строки
    using ip_info_t = std::tuple<boost::asio::ip::address_v4, boost::system::error_code>;

    /**
     * @brief Проверка валидности строки ip адреса
     * @details Максимальное значение = 15 байтам (строка "255.255.255.255")
     */
    static constexpr auto is_valid_size{
        [](auto &&rng) {
            static constexpr int kMaxNumLenIpStr{15};

            return std::ranges::distance(rng) <= kMaxNumLenIpStr;
        }
    };

    /**
     * @brief Проверка количества точек в строке ip адерса
     * @details В ip адресе должно быть 3 (строка "255.255.255.255")
     */
    static constexpr auto is_valid_num_points{
        [](auto &&rng) {
            static constexpr int kNumPoints{3};

            return std::ranges::count(rng, '.') == kNumPoints;
        }
    };

    /**
     * @brief Конвертация ip адреса строки в boost::asio::ip::address_v4 и состояние валидности ip адреса
     */
    static constexpr auto convert_to_ip{
        [](auto &&rng) {
            boost::system::error_code ec{};
            std::string const str{std::ranges::cbegin(rng), std::ranges::cend(rng)};
            auto const address{boost::asio::ip::address_v4::from_string(str, ec)};
            return ip_info_t{address, ec};
        }
    };

    /**
     * @brief Проверка валидности ip адреса по error code полученному при конвертации ip адресв
     */
    static constexpr auto is_valid_ip{
        [](ip_info_t const &ip) {
            static constexpr int kErrorCode{1};

            return !std::get<kErrorCode>(ip);
        }
    };

    /**
     * @brief Получение только ip адреса (boost::asio::ip::address_v4)
     * @details Вызывается после проверки валидности ip адреса
     */
    static constexpr auto get_ip{
        [](ip_info_t const &ip_info) {
            static constexpr int kIp{0};

            return std::get<kIp>(ip_info);
        }
    };
};

/**
 * @brief Класс фильтрации ip адресов
 */
class IpFilter : RangesFuncs {
public:
    /**
     * @brief Конструктор. Сохранить путь входного файла
     * @param file Путь до входного файла
     */
    explicit IpFilter(std::string const file);

    explicit IpFilter() = default;

    /**
     * @brief Парсинг входного файла
     * @details При парсинге входного файла заполняется контейнер с валидными ip адресами
     * @return
     * true - Файл был удачно обработан
     * false - Ошибка чтения входного файла
     */
    [[nodiscard]] bool ParsingInputFile();

    void ParsingInputVector(std::vector<std::string> const &in);

    /**
     * @brief Сортировка контейнера ip адресов получнных после парсинга входного файла
     * @param func Функция сортировки
     */
    void Sorting(std::function<bool(boost::asio::ip::address_v4 const &, boost::asio::ip::address_v4 const &)> func);

    /**
     * @brief Фильтрация ip адресов
     * @tparam Funcs Тип функции фильтации
     * @param funcs Функции фильтрации
     */
    template<class... Funcs>
    void Filter(Funcs... funcs) const {
        static constexpr int kEmpty{0};

        static_assert(sizeof...(Funcs) != kEmpty, "Error ...");

        using func_t = std::function<bool(boost::asio::ip::address_v4 const &)>;
        std::vector<func_t> vec_funcs{};
        (vec_funcs.push_back(funcs), ...);
        for (auto const &func: vec_funcs) {
            for (auto const &ip: ips | std::views::filter(func)) {
                std::cout << ip.to_string() << "\n";
            }
        }
    }

    /// Получить контейнер ip адресов после парсинга входных данных
    [[nodiscard]] std::vector<boost::asio::ip::address_v4> GetIPs() const;

    /// Версия патча
    static uint64_t Version();

private:
    /**
     * @brief Парсинг строки ip адреса
     * @param line Строка ip адреса
     */
    void parsing(std::string const &line);

private:
    /// Путь входного файла
    std::string const file{};
    /// Контейнер для хранения ip адресов после парсинга входного файла
    std::vector<boost::asio::ip::address_v4> ips{};
};
