#include "./Sniffer.h"
#include <iostream>

class DevSniffer : public Sniffer{

public:
    DevSniffer(const char* dev_name, int snaplen, int promisc, int to_ms) {
        dev = dev_name;
        descr = pcap_open_live(dev, snaplen, promisc, to_ms, errbuf);
        if (descr == NULL) {
            std::cout << "pcap_open_live() failed: " << errbuf << std::endl;
            return;
        }
    }
};