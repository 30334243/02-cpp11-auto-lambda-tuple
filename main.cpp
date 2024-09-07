#include <iostream>
#include "ip_filter.h"

int main() {
	IpFilter filter{};
	std::cout << "Version ip filter=" << filter.Version() << std::endl;
	return 0;
}