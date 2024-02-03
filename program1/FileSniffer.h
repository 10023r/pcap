#include "./Sniffer.h"
#include <iostream>

class FileSniffer : public Sniffer {
public:
    FileSniffer(const char* filename){
        descr = pcap_open_offline(filename, errbuf);
        if (descr == NULL) {
            std::cout << "Error while opening file: " << errbuf << std::endl;
        }
        if (pcap_findalldevs(&my_dev, errbuf))  {
            pcap_perror(descr, "Couldn't find appropriate device: ");
        }
        dev = my_dev->name;
    }

    ~FileSniffer(){
        pcap_freealldevs(my_dev);
    }
};