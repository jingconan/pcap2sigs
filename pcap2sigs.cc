/*#include <string.h>*/ /* For memcpy(3) */
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h> /* For random(3) */
#include <string.h> /* For strcmp() */
#include <sys/types.h>
#include <inttypes.h>

#include <iterator>
#include <map>
#include <vector>
#include <set>
#include <exception>
#include <ctime>
#include <cassert>
#include <iostream>
#include <algorithm>

extern "C" {
#include "constants.h"
#include "pcapSupport.h"
}

using std::distance;
using std::set;
using std::pair;
using std::vector;
using std::map;
using std::difftime;
using std::make_pair;
using std::ostream;
using std::cout;
using std::endl;
using std::string;
using std::binary_search;
using std::lower_bound;
using std::sort;
// using std::exception;
typedef unsigned int uint;

struct IP {
    IP (u_char q1, u_char q2, u_char q3, u_char q4) {
        this->q1 = q1;
        this->q2 = q2;
        this->q3 = q3;
        this->q4 = q4;
    }
    bool operator <(const IP& a) const
    {
        return (q1 < a.q1) || \
               ((q1 == a.q1) && (q2 < a.q2)) || \
               ((q1 == a.q1) && (q2 == a.q2) && (q3 < a.q3)) || \
               ((q1 == a.q1) && (q2 == a.q2) && (q3 == a.q3) && (q4 < a.q4));
    }

    void print() {
        cout << q1 << "." << q2 << "." << q3 << "." << q4 << endl;
    }


    u_char q1;
    u_char q2;
    u_char q3;
    u_char q4;
};



// struct MyTime {

// };
// typedef timeval TimeStruct;
//
typedef unsigned long ULInt;

class TimeStruct {
public:
    TimeStruct() {
    }
    TimeStruct(timeval tv) {
        stored_time_ = tv;
    }
    TimeStruct(ULInt sec, ULInt usec) {
        stored_time_.tv_sec = sec;
        stored_time_.tv_usec = usec;
    }
    // timeval getTime() {
    //     return stored_time_;
    // }
    ULInt getSec() const {
        return stored_time_.tv_sec;
    }

    ULInt getUSec() const {
        return stored_time_.tv_usec;
    }

    friend bool operator<(const TimeStruct & a, const TimeStruct & b) {
        return timercmp(&(a.stored_time_), &(b.stored_time_), <);
    }

    void add (const TimeStruct & b) {
        timeradd(&(this->stored_time_), &(b.stored_time_),
              &(this->stored_time_));
    }

    timeval stored_time_;
};

TimeStruct difftime(TimeStruct & a, TimeStruct & b) {
    int as = a.getSec(), au = a.getUSec();
    int bs = b.getSec(), bu = b.getUSec();
    if (au < bu) {
        au += 1000000; //Note be careful about overflow
        as -= 1;
    }
    assert(as >= bs);
    return TimeStruct(as - bs, au - bu);
}

typedef pair<IP, IP> SDPair;
typedef map<SDPair, int> Graph;
typedef vector<Graph> GraphVec;
typedef set<IP> NodeSet;
typedef vector<IP> NodeVec;


ostream& operator<<(ostream & os, const TimeStruct & v) {
    os << v.getSec() << "." << v.getUSec() << endl;
    return os;
}


ostream& operator<<(ostream & os, const IP & v) {
    os << (uint)v.q1 << "." 
       << (uint)v.q2 << "." 
       << (uint)v.q3 << "." 
       << (uint)v.q4;
    return os;
}


ostream& operator<<(ostream & os, const SDPair & v) {
    os << v.first << " -> " << v.second;
    return os;
}


ostream& operator<<(ostream & os, const Graph & v) {
    Graph::const_iterator it;
    for(it = v.begin(); it != v.end(); ++it) {
        os << it->first << endl;
    }
    return os;
}




// class NotInitialized: public exception {
//     virtual const char* what() const throw() {
//         return ""
//     }
// };

class SIGAnalyzer {
public:
    SIGAnalyzer (TimeStruct interv_size, bool print) {
        print_ = print;
        interv_size_ = interv_size;
        sigs_.push_back(Graph());
    }

    SDPair checkPkt(const packet_struct & pkt, const pcap_pkthdr & hdr) {
        TimeStruct pkt_time = getPktTime(hdr);
        if (print_) {
            if (max_time_ < pkt_time) {
                max_time_ = pkt_time;
            }
        }
        SDPair sd = getPktSDPair(pkt);

        // Create new SIG if time out
        if (interv_size_ < difftime(pkt_time, last_interv_stime_)) {
            last_interv_stime_.add(interv_size_);
            sigs_.push_back(Graph());
        }

        Graph & sig = sigs_.back();
        Graph::iterator it = sig.find(sd);
        if (it != sig.end()) {
            ++(it->second);
        } else {
            sig[sd] = 1;
            if (print_) { cout << "Edge " << sig.size() << ": " << sd << endl; }
        }
        return sd;
    }

    void write(ostream &out) {
        for (size_t i = 0; i < sigs_.size(); ++i) {
            out << "G" << i << endl;
            out << sigs_[i];
        }
    }

    void write(ostream &out, const NodeVec & nv) {
        // for each graph
        int s1, s2;
        for (size_t i = 0; i < sigs_.size(); ++i) {
            out << "G" << i << endl;
            Graph::const_iterator it;
            const Graph & v = sigs_[i];
            // for each edge
            for(it = v.begin(); it != v.end(); ++it) {
                s1 = std::lower_bound(nv.begin(), nv.end(), it->first.first) - nv.begin();
                s2 = std::lower_bound(nv.begin(), nv.end(), it->first.second) - nv.begin();
                out << s1 << " -> " << s2 << endl;
            }
        }
    }

    void debugInfo() {
        TimeStruct td = difftime(max_time_, min_time_);
        cout << "Time Range: " << td.getSec() << "." << td.getUSec() << endl;
    }


    void setInitialTime(TimeStruct init_time) {
        last_interv_stime_ = init_time;
        min_time_ = init_time;
        max_time_ = init_time;
        initialized_ = true;
    }

    int setInterval(TimeStruct interv_size) {
        if (!initialized_) {
            return -1;
        }
        interv_size_ = interv_size;
    }

    TimeStruct getPktTime(const pcap_pkthdr &hdr) {
        return hdr.ts;
    }

    SDPair getPktSDPair(const packet_struct &pkt) {
        return make_pair(IP(pkt.srcIpQ1, pkt.srcIpQ2, pkt.srcIpQ3, pkt.srcIpQ4), 
                IP(pkt.dstIpQ1, pkt.dstIpQ2, pkt.dstIpQ3, pkt.dstIpQ4));
    }
private:
    bool initialized_;
    bool print_;
    TimeStruct last_interv_stime_;
    TimeStruct interv_size_;
    GraphVec sigs_;

    TimeStruct min_time_;
    TimeStruct max_time_;
};

#define USEC_LEN 6
#define PT_ICMP 1
#define PT_IP 4
#define PT_TCP 6
#define PT_UDP 17


int parseIntervalSize(const char * str, ULInt & sec, ULInt & usec) {
    bool only_secs = false;
    string s(str);
    int pos = s.find(".");
    if (pos == -1) {
        only_secs = true;
        pos = s.size();
    }

    string sec_str = s.substr(0, pos);
    if (sec_str.size() >= 20) {
        cout << "input invalid: second in <interval_size> too large" << endl;
        return -1;
    }
    sec = atoll(sec_str.c_str());

    if (only_secs) {
        usec = 0;
        return 0;
    } 

    string usec_str = s.substr(pos+1, s.size());
    if ((usec_str.size() <= 0) || (usec_str.size() > USEC_LEN)) {
        cout << "input invalid: usecond in <interval_size> has too many digits" << endl;
        return -1;
    }
    usec = atoll(usec_str.c_str());
    for (int i = usec_str.size(); i < USEC_LEN; ++i) {
            usec *= 10;
    }
    return 0;
}

int main(int argc, char** argv) 
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <infile> <interval_size> [-debug]\n", argv[0]);
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* infile = pcap_open_offline(argv[1], errbuf);
    if (infile == null) {
        fprintf(stderr, "Unable to open %s: %s", argv[1], errbuf);
        return -2;
    }
    int dlt = pcap_datalink(infile);

    set_link_type(dlt);


    ULInt sec, usec;
    if (parseIntervalSize(argv[2], sec, usec) < 0) {
        return -1;
    }

    bool debug_flag = false;
    if ( (argc == 4) && (strcmp(argv[3], "-debug")==0) ) {
        debug_flag = true;
    }
    
    if (debug_flag) { printf("dlt: %i DLT_RAW: %i\n", dlt, DLT_RAW); }

    struct pcap_pkthdr pkthdr;
    TimeStruct interv_size(sec, usec);
    SIGAnalyzer ana(interv_size, debug_flag);
    NodeSet nodes;
    bool first = true;
    unsigned long long pkt_num = -1;

    while (true) {
        ++pkt_num;
        const u_char* packet = pcap_next(infile, &pkthdr);

        if (packet == null) break;
        // if (debug_flag) printf("Captured %u out of %u bytes: \n", pkthdr.caplen, pkthdr.len);

        struct packet_struct ps;
        unpack_packet(packet, &ps, pkthdr.caplen);
        // printf("port %d\n", ps.srcPort);
        if (first) {
            ana.setInitialTime(pkthdr.ts);
            first = false;
        }

        /* ICMP (1), TCP (6) or UDP (17)*/
        u_char prot = ps.protocol;
        bool prot_flag = false;
#ifdef E_IP
        if (prot == PT_IP) {
            prot_flag = true;
        }
        if (debug_flag) printf("Test PT_IP\n");
#endif
#ifdef E_TCP
        if (prot == PT_TCP) {
            prot_flag = true;
        }

        // if (debug_flag) printf("Test PT_TCP\n");
#endif
#ifdef E_ICMP
        if (prot == PT_ICMP) {
            prot_flag = true;
        }
        // if (debug_flag) printf("Test PT_ICMP\n");
#endif
#ifdef E_UDP
        if (prot == PT_UDP) {
            prot_flag = true;
        }
        // if (debug_flag) printf("Test PT_UDP\n");
#endif

#ifdef E_ALL
        prot_flag = true;
#endif

        if (prot_flag) {
            SDPair sd = ana.checkPkt(ps, pkthdr);
            nodes.insert(sd.first);
            nodes.insert(sd.second);

            if (debug_flag) { 
                printf("ts: %ld.%ld, src ip: %u.%u.%u.%u, dst ip: %u.%u.%u.%u, proto: %i\n", 
                        pkthdr.ts.tv_sec,
                        pkthdr.ts.tv_usec,
                        ps.srcIpQ1, 
                        ps.srcIpQ2,
                        ps.srcIpQ3,
                        ps.srcIpQ4, 
                        ps.dstIpQ1,
                        ps.dstIpQ2,
                        ps.dstIpQ3,
                        ps.dstIpQ4, 
                        ps.protocol);
            }
        }
    }

    pcap_close(infile);

    NodeSet::iterator sit;
    for (sit = nodes.begin(); sit != nodes.end(); ++sit) {
        cout << *sit << ' ';
    }
    cout << endl;
    NodeVec nv(nodes.begin(), nodes.end());
    sort(nv.begin(), nv.end());
    ana.write(cout, nv);
    if (debug_flag) ana.debugInfo();
    if (debug_flag) cout << "IP num: " << nv.size() << endl;
    if (debug_flag) cout << "Total Packet Num: " << pkt_num << endl;

    return 0;
}
