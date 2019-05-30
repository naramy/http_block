//          Copyright Joe Coder 2004 - 2006.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          https://www.boost.org/LICENSE_1_0.txt)

#include <iostream>
#include <pcap.h>
#include <vector>                               //std::vector
#include <list>                                 //std::list
#include <thread>                               //std::thread
#include <regex>                                //std::regex
#include <cmath>                                //log10()
#include <fstream>                              //std::ifstream, std::ofstream
#include <unordered_set>                        //std::unordered_set
//#include <iterator>
#include <arpa/inet.h>				//inet_ntop()
#include <cstring>				//memcmp(), strncpy()
#include <net/ethernet.h>			//struct ether_header, ETHERTYPE
#include <netinet/ip.h>				//struct ip, IPPROTO
#include <netinet/tcp.h>			//struct tcphdr
#include <boost/noncopyable.hpp>		//boost::noncopyable
#include <boost/move/unique_ptr.hpp>		//boost::unique_ptr
#include <boost/move/make_unique.hpp>		//boost::make_unique
#include <boost/smart_ptr/shared_ptr.hpp>	//boost::shared_ptr
#include <boost/make_shared.hpp>		//boost::make_shared
#include <boost/smart_ptr/weak_ptr.hpp>		//boost::weak_ptr

using boost::movelib::unique_ptr;
using boost::movelib::make_unique;
using boost::make_shared;
using boost::weak_ptr;

#define MAX 255
#define MTU 1500

bool static block_chk = false;
bool static thread_lock = true;
auto static block_site(make_unique<char*>(new char[MAX]));
static std::unordered_set<std::string> site;
static std::regex pattern("(Host:) ([^\r\n]+)");

#pragma pack(push, 1)
struct separated_tls {
    uint8_t     content_type;
    uint16_t    t_ver;
    uint16_t    t_len;
    __extension__ union {
        struct {
            uint8_t     handshake_type;
            uint8_t     p_len[3];
            uint16_t    p_ver;
            uint32_t    random[8];
            uint8_t     sid_len;
        };
    };
};
#pragma pack(pop)

class Header : private boost::noncopyable {
    protected:
        virtual void print();
    public:
        Header() {}
        virtual ~Header() {}
};

class Ethhdr : protected Header {
    private:
        const struct ether_header *ether;
    protected:
        void macprint(const uint8_t *src) {
            for(int i{}; i < ETH_ALEN; i++)
                printf("%02X:", *(src + i));
            printf("\b \n");
        }
        void broadcast() {
            uint8_t *tmp = const_cast<uint8_t *>(ether->ether_dhost);
            for(int i{}; i < ETH_ALEN; i++) {
                tmp[i] = 0xff;
            }
        }
    public:
        Ethhdr() { this->ether = nullptr; }
        Ethhdr(const u_char **packet) {
            this->ether = reinterpret_cast<const struct ether_header *>(*packet);
            //*packet += sizeof(ether_header);
        }
        ~Ethhdr() override { this->ether = nullptr; }
        uint16_t getEthertype() { return ntohs(this->ether->ether_type); }
        void print() override;
        void ether_build(bool reverse) {
            if(reverse) {
                auto tmp(make_unique<uint8_t *>
                         (static_cast<uint8_t *>(calloc(ETH_ALEN, sizeof(uint8_t)))));
                memcpy(*tmp, const_cast<uint8_t *>(ether->ether_dhost),
                       sizeof(ether->ether_dhost));
                memcpy(const_cast<uint8_t *>(ether->ether_dhost),
                       const_cast<uint8_t *>(ether->ether_shost),
                       sizeof(ether->ether_dhost));
                memcpy(const_cast<uint8_t *>(ether->ether_shost),
                       *tmp, sizeof(ether->ether_shost));
            }
        }
};

class Iphdr : protected Header {
    private:
        const struct ip *ip;
    public:
        Iphdr() { this->ip = nullptr; }
        Iphdr(const u_char **packet) {
            ip = reinterpret_cast<const struct ip *>(*packet + sizeof(ether_header));
            //*packet += (this->ip->ip_hl << 2);
        }
        ~Iphdr() override { this->ip = nullptr; }
        void print() override;
        void ip_build(bool reverse) {
            srand(static_cast<unsigned int>(time(nullptr)));
            const uint8_t &tmp = ip->ip_ttl;
            uint8_t &to_flag = const_cast<uint8_t &>(tmp);
            to_flag = static_cast<uint8_t>(rand() % 33 + 96);   //TTL -> 96 ~ 128

            if(reverse) {
                struct in_addr tmp = *(const_cast<struct in_addr *>(&ip->ip_dst));
                memcpy(const_cast<struct in_addr *>(&ip->ip_dst),
                       const_cast<struct in_addr *>(&ip->ip_src),
                       sizeof(ip->ip_dst));
                memcpy(const_cast<struct in_addr *>(&ip->ip_src),
                       &tmp, sizeof(ip->ip_src));
            }
        }
        uint16_t getIplen() const { return ntohs(this->ip->ip_len); }
        uint8_t getIphl() const { return this->ip->ip_hl; }
        uint8_t getIpproto() const { return this->ip->ip_p; }
        uint32_t getSip() const { return ntohl(ip->ip_src.s_addr); }
        uint32_t getDip() const { return ntohl(ip->ip_dst.s_addr); }
        const struct ip* getIp() const { return this->ip; }
};

class Tcphdr : protected Header {
    private:
        struct tcphdr *tcp;
        uint32_t payload_len;
    public:
        Tcphdr() { this->tcp = nullptr; }
        //Tcphdr(const u_char **packet, weak_ptr<Iphdr> cp_ip) {
        Tcphdr(weak_ptr<Iphdr> cp_ip) {
            if(auto ip = cp_ip.lock()) {
                //const struct ip* mip = ip->getIp();
                tcp = reinterpret_cast<struct tcphdr *>
                        (reinterpret_cast<u_char *>
                         (const_cast<struct ip *>(ip->getIp())) +
                        (ip->getIphl() << 2));
                payload_len = static_cast<uint32_t>(ip->getIplen() -
                        (ip->getIphl() << 2) - (getThoff() << 2));
                /* case 1 (OK. but http data parsing failed.)
                tcp = reinterpret_cast<const struct tcphdr *>
                        (ip->getIp() + (ip->getIphl() << 2) /
                         static_cast<int>(sizeof(struct ip)));
                ** case 2
                tcp = reinterpret_cast<const struct tcphdr *>
                        (*packet + sizeof(ether_header) +
                         ip->getIphl() << 2));
                //(*packet) += (getThoff() << 2);
                **/
            }
        }
        ~Tcphdr() override { this->tcp = nullptr; }
        void print() override;
        template<typename T>
        void changeFlag(T &from_flag, T &data) {
            const T &tmp = from_flag;
            T &to_flag = const_cast<T &>(tmp);
            to_flag += data;
        }
        template<typename T>
        void swapFlag(T &from, T &to) {
            T tmp = from;
            from = to;
            to = tmp;
        }
        void tcp_build(bool reverse) {
            tcp->ack = 0x01;
            tcp->rst = 0x01;

            if(reverse) {
                swapFlag(const_cast<uint32_t &>(tcp->th_seq),
                         const_cast<uint32_t &>(tcp->th_ack));
                swapFlag(const_cast<uint16_t &>(tcp->th_sport),
                         const_cast<uint16_t &>(tcp->th_dport));
                changeFlag(const_cast<uint32_t &>(tcp->th_ack),
                           static_cast<uint32_t &>(payload_len));
            } else {
                changeFlag(const_cast<uint32_t &>(tcp->th_seq),
                           static_cast<uint32_t &>(payload_len));
            }
            if(getThsport() != 443 && getThdport() != 443)  //https X -> TCP payload X
                memset(const_cast<char *>(reinterpret_cast<const char *>(tcp)) +
                        (tcp->th_off << 2), 0x00, payload_len);
        }
        uint16_t getThsport() const { return ntohs(this->tcp->th_sport); }
        uint16_t getThdport() const { return ntohs(this->tcp->th_dport); }
        uint8_t getThoff() const { return this->tcp->th_off; }
        uint32_t getPayloadlen() const { return payload_len; }
        const struct tcphdr* getTcp() const { return this->tcp; }
};

class Httphdr : protected Header {
    private:
        const struct separated_tls *tls;
        const u_char *packet;
        uint32_t len;    //for memory -> int to short
        bool is_http;
        bool is_https;
        const char * const http_method[8] = {
            "CONNECT", "TRACE", "OPTIONS", "DELETE",
            "PUT", "HEAD", "POST", "GET"};
    public:
        Httphdr() { packet = nullptr; tls = nullptr; }
        //Httphdr(const u_char **packet, weak_ptr<Iphdr> cp_ip, weak_ptr<Tcphdr> cp_tcp) {
        Httphdr(weak_ptr<Iphdr> cp_ip, weak_ptr<Tcphdr> cp_tcp) {
            auto ip = cp_ip.lock();
            auto tcp = cp_tcp.lock();
            if(ip && tcp) {
                this->len = tcp->getPayloadlen();
                this->packet = reinterpret_cast<const u_char *>
                        (reinterpret_cast<const u_char *>(tcp->getTcp()) +
                         (tcp->getThoff() << 2));
                /* case 1 - failed
                this->packet = reinterpret_cast<const u_char *>
                        (tcp->getTcp() + (tcp->getThoff() << 2) /
                         static_cast<int>(sizeof(struct tcphdr)));
                ** case 2 - OK
                //this->packet = *packet + sizeof(ether_header) +
                        (ip->getIphl() << 2) + (tcp->getThoff() << 2);
                ** case 3 -> required "*packet += ...;" - OK
                //this->packet = *packet;
                **/
                Ishttp(tcp->getThsport(), tcp->getThdport());

                if(is_https) {
                    tls = reinterpret_cast<const struct separated_tls *>(packet);
                    if(tls->content_type == 0x16 &&       //Handshake(22)
                            tls->handshake_type == 0x01) { //Client Hello(1)
                        packet += (sizeof(struct separated_tls));
                        uint16_t random_len = *(packet - 1);
                        packet += (random_len + 2);
                        uint16_t cs_len = *(packet - 1);   //Cipher Suite Length
                        packet += cs_len;
                        uint8_t cm_len = *(packet); //Compression Method Length
                        packet += cm_len + 2;
                        packet += sizeof(uint16_t) * 5; //skip elements
                        uint16_t sn_len = *(packet - 1); //find server name length
                        //printf("%04x %04x\n", *(packet - 1) & 0xff, *(packet - 1));
                        memset(*block_site, 0x00, MAX); //block_site will be empty
                        memcpy(*block_site, packet, sn_len);
                        printf("Server Name : %s\n", *block_site);
                    }
                } else { tls = nullptr; }
            }
        }
        ~Httphdr() final { packet = nullptr; tls = nullptr; }
        void Ishttp(uint16_t src, uint16_t dst) {
            if((src == 80 || dst == 80) && this->len) {
                int i = sizeof(http_method)/sizeof((*http_method));
                while(i--) {
                    if(memcmp(http_method[i], reinterpret_cast<const char *>(packet),
                              strlen(http_method[i])) == 0) {
                        is_http = true;
                        is_https = false;
                        return;
                    }
                }
            } else if((src == 443 || dst == 443) && len) {
                is_http = false;
                is_https = true;
                return;
            }
            is_http = false;
            is_https = false;
        }
        bool Ishttp() { return is_http; }
        uint32_t getHttplen() { return len; }
        void print() final;
        void find() {
            if(is_http) {
                std::string str(reinterpret_cast<const char *>(packet),
                                static_cast<unsigned long>(len));
                std::smatch m;

                if(regex_search(str, m, pattern)) {
                    for(size_t i = 0; i < m.size(); i++)
                        printf("m[%d] : %s\n", static_cast<int>(i), m.str(i).c_str());

                if(site.find(m.str(2).c_str())
                    != site.end()) {
                        puts("find!");
                        block_chk = true;
                        //http dump
                        extern void dump(const u_char*, int);
                        dump(packet, static_cast<int>(len));
                    }
                }
            } else if(is_https) {
                if(site.find(static_cast<std::string>(*block_site))
                        != site.end()) {
                    puts("find!");
                    block_chk = true;
                }
            }
            thread_lock = false;
        }
};

void Header::print() {
    puts("Header print");
}

void Ethhdr::print() {
    printf("Source MAC Address : ");
    macprint(ether->ether_shost);
    printf("Destination MAC Address : ");
    macprint(ether->ether_dhost);
    printf("Ether Type : %04x\n", getEthertype());
}

void Iphdr::print() {
    char src_buf[16], dst_buf[16];

    inet_ntop(AF_INET, &this->ip->ip_src.s_addr, src_buf, sizeof(src_buf));
    inet_ntop(AF_INET, &this->ip->ip_dst.s_addr, dst_buf, sizeof(dst_buf));
    printf("Source IP Address : %s\n", src_buf);
    printf("Destination IP Address : %s\n", dst_buf);
}

void Tcphdr::print() {
    printf("Source Port Address : %d\n", this->getThsport());
    printf("Destination Port Address : %d\n", this->getThdport());
}

void Httphdr::print() {
    //if(this->len > 16)	this->len = 16;
    if(is_http) {
        printf("Http Data : ");
        int i{};
        while(i < static_cast<int>(this->len))
            printf("%c", *(this->packet + i++));
        if(*(this->packet + --i) != '\n') putchar('\n');
    }
}

void dump(const u_char *buf, int size) {
    for(int i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", buf[i]);
    }
    putchar('\n');
}

void usage(char *argv) {
    printf("syntax: %s\n", argv);
    printf("sample: %s\n", argv);
    /*
    printf("syntax: %s <target IP>\n", argv);
    printf("sample: %s 192.168.0.2\n", argv);
    */
}

int setPcap(pcap_t **handle) {
    char errbuf[PCAP_ERRBUF_SIZE];
    std::vector<char *> dev;
    //char *dev = pcap_lookupdev(errbuf);
    pcap_if_t *alldevs = nullptr;
    int i{}, num{};

    if(pcap_findalldevs(&alldevs, errbuf) >= 0) {
        for(pcap_if_t *d = alldevs; d; d = d->next) {
            dev.push_back(d->name);
            printf("%d. %s\n", i++, d->name);
        }

        while(i) {
            printf("\nChoose the interface number (0-%d) : ", i - 1);
            scanf("%d", &num);
            if(num < 0 || num > i - 1) {
                puts("This number is out of range.");
                continue;
            }
            //dev.at() -> std::out_of_range error can find
            *handle = pcap_open_live(dev[static_cast
                        <std::vector<char *>::size_type>(num)],
                        65536, 1, 1, errbuf);
            pcap_freealldevs(alldevs);
            return 0;
        }
    }

    fprintf(stderr, "couldn't found device\n");
    return -1;
}

bool file_exist(const char *fileName) {
    std::ifstream file(fileName);
    bool result = file.good();
    file.close();

    return result;
}

int main(int argc, char* argv[]) {
    bool test_opened;
    int res;
    double fseek_num{};
    std::vector<void *> ptr_manager;
    FILE *fp = nullptr;
    pcap_t* handle = nullptr;
    struct pcap_pkthdr *header = nullptr;
    //const struct in_addr *tip = nullptr;
    std::list<const u_char *> pkt;
    const u_char *packet = nullptr,
          *toClient = static_cast<const u_char *>
                        (calloc(MTU, sizeof(u_char))),
          *toServer = static_cast<const u_char *>
                        (calloc(MTU, sizeof(u_char)));

    ptr_manager.push_back(fp);
    ptr_manager.push_back(handle);
    ptr_manager.push_back(header);
    //ptr_manager.push_back(const_cast<struct in_addr *>(tip));
    ptr_manager.push_back(const_cast<u_char *>(packet));
    ptr_manager.push_back(const_cast<u_char *>(toServer));
    ptr_manager.push_back(const_cast<u_char *>(toClient));
    pkt.push_back(toClient);
    pkt.push_back(toServer);

    switch(argc) {
        /*
        case 2:
            tip = reinterpret_cast<const struct in_addr *>(argv[1]);
            break;
        */
        case 1:
            break;
        default:
            usage(argv[0]);
            goto _end;
    }

    if(setPcap(&handle) == -1) goto _end;

    if(file_exist("test.csv")) {
        test_opened = true;
        fseek_num = 0;
        fp = fopen("test.csv", "r");
        puts("test.csv is opened");
    } else if(file_exist("top-1m.csv")) {
        test_opened = false;
        fseek_num = 2;
        fp = fopen("top-1m.csv", "r");
        puts("top-1m.csv is opened");
    } else {
        fprintf(stderr, "csv file can not be found.\n");
        goto _end;
    }

    for(double i = 1; i <= 1000000; i++) {
        if(!test_opened && static_cast<int>(i) % 10 == 0)
            fseek_num = static_cast<int>(log10(i)) + 2;
        fseek(fp, static_cast<long>(fseek_num), SEEK_CUR);
        fgets(*block_site, MAX, fp);
        int j = static_cast<int>(strlen(*block_site)/sizeof((*block_site)[0]));
        while(--j)
            if((*block_site)[j] == 0x0A) { (*block_site)[j] = 0x00; break; }
        site.insert(static_cast<std::string>(*block_site));
    }
    fclose(fp);

    if(!test_opened) {
        std::string filePath = "test.csv";
        std::ofstream writeFile(filePath.data());
        if(writeFile.is_open()) {
            for(std::unordered_set<std::string>::iterator it = site.begin();
                it!=site.end(); ++it) {
                writeFile << *it;
                writeFile << "\n";
            }
            writeFile.close();
            puts("test.csv is written");
        } else {
            puts("test.csv can't be written");
        }
    }

    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) continue;

        putchar('\n');
        puts("--------------------------------------------");
        auto ether(make_unique<Ethhdr>(&packet));
        ether->print();
        if(ether->getEthertype() == ETHERTYPE_IP) {
            auto ip(make_shared<Iphdr>(&packet));
            ip->print();
            if(ip->getIpproto() == IPPROTO_TCP) {
                auto tcp(make_shared<Tcphdr>(ip));
                tcp->print();
                uint16_t sport = tcp->getThsport(), dport = tcp->getThdport();
                if(sport == 80 || dport == 80 || sport == 443 || dport == 443) {
                    auto http(make_shared<Httphdr>(ip, tcp));
                    /* case 1 - using lambda & weak_ptr
                    std::thread find([](weak_ptr<Httphdr> cp_http) {
                        auto http = cp_http.lock();
                        if(http)    http->find();
                        //cp_http.lock()->find();   //Compiler doesn't find error. nullptr->find()?
                    }, http);
                    */
                    std::vector<std::thread> th_manager;
                    std::thread find{&Httphdr::find, http};
                    std::thread rst_thread([&pkt, &packet, &handle, &ip, &http]() {
                        int i{}, len{};

                        if(http->Ishttp())
                            len = static_cast<int>(sizeof(ether_header) + ip->getIplen()
                                                                    - http->getHttplen());
                        else
                            len = static_cast<int>(sizeof(ether_header) + ip->getIplen());

                        for(std::list<const u_char *>::iterator iter = pkt.begin();
                                iter != pkt.end(); ++iter, i++) {
                            if(len > MTU)   break;
                            memcpy(const_cast<u_char *>(*iter), packet,
                                                static_cast<size_t>(len));
                            auto rst_ether(make_unique<Ethhdr>(&(*iter)));
                            auto rst_ip(make_shared<Iphdr>(&(*iter)));
                            auto rst_tcp(make_shared<Tcphdr>(rst_ip));
                            rst_ether->ether_build(i % 2);
                            rst_ip->ip_build(i % 2);
                            rst_tcp->tcp_build(i % 2);
                        }
                        i = i ^ i;

                        while(block_chk == false && thread_lock);
                        if(block_chk) {
                            for(std::list<const u_char *>::iterator iter = pkt.begin();
                                    iter != pkt.end(); ++iter, i++)
                                pcap_sendpacket(handle, *iter, len);
                            block_chk = false;
                        } else {
                            thread_lock = true;
                        }
                    });
                    th_manager.push_back(std::move(find));
                    th_manager.push_back(std::move(rst_thread));
                    for(const std::thread &th : th_manager)
                        if(th.joinable())   const_cast<std::thread &>(th).join();
                    /* case 1 - using iterator
                    for(std::vector<std::thread>::iterator it = th_manager.begin();
                            it != th_manager.end(); ++it)
                        if(it->joinable())      it->join();
                    // case 2
                    //if(find.joinable())         find.join();
                    //if(rst_thread.joinable())   rst_thread.join();
                    */
                }
            }
        }
        puts("--------------------------------------------");
    }

    pcap_close(handle);
_end:
    for(auto &it : ptr_manager) {
        free(it);
        it = nullptr;
    }

    /*
    std::vector<void *>::iterator end = ptr_manager.end();
    for(std::vector<void *>::iterator iter = ptr_manager.begin();
            iter != end; ++iter) {
        free(*iter);
        *iter = nullptr;
    }
    */

    return 0;
}
