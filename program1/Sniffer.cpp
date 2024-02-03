#include "./Sniffer.h"

void Sniffer::set_filter(const char* filter, int mode) {
    if (pcap_lookupnet(dev, &net, &mask, errbuf)) {
        pcap_perror(descr, "Can't get netmask for device: ");
    }
    if (pcap_compile(descr, &fcode, filter, mode, net) < 0) {
        pcap_perror(descr, "Cannot compile filter: ");
    }
    if (pcap_setfilter(descr, &fcode) < 0) {
        pcap_perror(descr, "Cannot set filter: ");
    }
}


void Sniffer::set_handler(int packets_to_process, pcap_handler handler, u_char* user_args) {
    if (pcap_loop(descr, packets_to_process, handler, user_args) < 0) {
        pcap_perror(descr, "pcap_loop() failed: ");
    }
}

Sniffer::~Sniffer() {
    pcap_close(descr);
    pcap_freecode(&fcode);
}