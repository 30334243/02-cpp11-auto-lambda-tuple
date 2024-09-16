#include <boost/asio/ip/address_v4.hpp>
#include "ip_filter.h"

int main() {
    static constexpr int kOk{0};
    static constexpr int kErrorIpFilter{1};
    static char const *const kInputFile{"ip_filter.tsv"};

    int ret{kOk};
    IpFilter ip_filter{kInputFile};
    if (!ip_filter.ParsingInputFile()) {
        ret = kErrorIpFilter;
    } else {
        ip_filter.Sorting(std::greater{});
        ip_filter.Filter(Otus::task_1, Otus::task_2, Otus::task_3, Otus::task_4);
    }
    return ret;
}
