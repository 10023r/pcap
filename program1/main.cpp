#include "pcap.h"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <iostream>
#include <map>
#include <utility>
#include <sstream>
#include <fstream>
#include "./FileSniffer.h"
#include "./DevSniffer.h"
#include "./FileWriter.h"
#define FILTER_STR "tcp or udp"
#define CSV_FILENAME "prog1_res.csv"
// #define FILENAME "./example.pcap"

using namespace std;

void packetHandler(u_char *user_args, const struct pcap_pkthdr* p_hdr, const u_char* packet);

int main(int argc, char *argv[]) {

    if (argc != 2) {
        cout << "Pass the path to .pcap file as a second argument.\n";
        return -1;
    }
    char* filename = argv[1];

    Sniffer* sniffer = new FileSniffer(filename);
    // Sniffer* sniffer = new DevSniffer("any", BUFSIZ, 1, 5000);
    map<string, pair<int, int>> data;
    sniffer->set_filter(FILTER_STR);
    sniffer->set_handler(5000, packetHandler, (u_char*)&data);
    cout << "Capturing finished.\n";
    FileWriter fw(CSV_FILENAME);
    for (auto x: data) {
        fw << x.first << "," << x.second.first << "," << x.second.second << endl;
    }
    delete sniffer;

    return 0;
}


void packetHandler(u_char *user_args, const struct pcap_pkthdr* p_hdr, const u_char* packet) {
    struct ether_header *e_hdr;
    struct ip *ip_hdr;
    struct tcphdr *t_hdr;
    struct udphdr *u_hdr;
    map<string, pair<int, int>>* user_data = (map<string, pair<int, int>>*)user_args;

    if (p_hdr->len < sizeof(struct ether_header)) { // Defective packet
        return;
    }
    e_hdr = (struct ether_header *)packet;

    if (ntohs(e_hdr->ether_type) != ETHERTYPE_IP) { // This packet is not IPv4
        return;
    }
    
    ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
    int ip_size = ip_hdr->ip_hl * 4;
    if (ip_hdr->ip_v != 4) {
        return;
    }

    uint16_t port_src, port_dst;
    if (ip_hdr->ip_p == 6) { // TCP == 6
        t_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_size);
        port_src = ntohs(t_hdr->source);
        port_dst = ntohs(t_hdr->dest);

    } else if (ip_hdr->ip_p == 17) { // UDP == 17
        u_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_size);
        port_src = ntohs(u_hdr->source);
        port_dst = ntohs(u_hdr->dest);

    } 
    string ip_src = inet_ntoa(ip_hdr->ip_src),
        ip_dst = inet_ntoa(ip_hdr->ip_dst);
    
    stringstream ss;
    ss << ip_src <<  "," << ip_dst << "," << port_src << "," << port_dst;
    string key = ss.str();
    if (user_data->find(key) == user_data->end()) {
        user_data->emplace(key, make_pair(1, p_hdr->caplen));
    } else {
        auto it = user_data->find(key)->second;
        it.first++;
        it.second += p_hdr->caplen;
    }
}