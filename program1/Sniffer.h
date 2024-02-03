#pragma once
#include "pcap.h"

class Sniffer {
protected:
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net, mask;
    bpf_program fcode;
    pcap_t* descr = nullptr;  // session descriptor
    pcap_if_t* my_dev = nullptr; // devices
    const char* dev = nullptr;
    Sniffer() = default;
public:
    virtual void set_filter(const char* filter, int mode=1);
    
    void set_handler(int packets_to_process, pcap_handler handler, u_char* user_args=NULL);

    ~Sniffer();
};