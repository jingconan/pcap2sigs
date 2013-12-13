/*#include <string.h>*/ /* For memcpy(3) */
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h> /* For random(3) */
#include <string.h> /* For strcmp() */
#include <sys/types.h>
#include <inttypes.h>

#include <map>
#include <vector>
#include <exception>
#include <ctime>
#include <cassert>

extern "C" {
#include "constants.h"
#include "pcapSupport.h"
}

using std::pair;
using std::vector;
using std::map;
using std::difftime;
// using std::exception;

struct IP {
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
    ULInt getSec() {
        return stored_time_.tv_sec;
    }

    ULInt getUSec() {
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

// class NotInitialized: public exception {
//     virtual const char* what() const throw() {
//         return ""
//     }
// };

class SIGAnalyzer {
public:
    void checkPkt(const packet_struct & pkt) {
        TimeStruct pkt_time = getPktTime(pkt);
        SDPair sd = getPktSDPair(pkt);
        if (interv_size_ < difftime(pkt_time, last_interv_stime_)) {
            last_interv_stime_.add(interv_size_);
            sigs_.push_back(Graph());
        }
        Graph sig = sigs_.back();
        Graph::iterator it = sig.find(sd);
        if (it == sig.end()) {
            sig[sd] = 1;
        } else {
            it->second += 1;
        }
    }


    void setInitialTime(TimeStruct init_time) {
        last_interv_stime_ = init_time;
        initialized_ = true;
    }

    int setInterval(TimeStruct interv_size) {
        if (!initialized_) {
            return -1;
        }
        interv_size_ = interv_size;
    }

    TimeStruct getPktTime(const packet_struct &pkt) {
        // Stub
    }
    SDPair getPktSDPair(const packet_struct &pkt) {
        // Stub
    }
private:
    bool initialized_;
    TimeStruct last_interv_stime_;
    TimeStruct interv_size_;
    GraphVec sigs_;
};

int main(int argc, char** argv) 
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <infile> <outfile> [-print]\n", argv[0]);
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* infile = pcap_open_offline(argv[1], errbuf);
    if (infile == null) {
        fprintf(stderr, "Unable to open %s: %s", argv[1], errbuf);
        return -2;
    }

    int print_flag = 0;
    if ( (argc > 3) && (strcmp(argv[3], "-print")==0) ) {
        print_flag = 1;
    }

    struct pcap_pkthdr pkthdr;

    while (true) {
        const u_char* packet = pcap_next(infile, &pkthdr);

        if (packet == null) break;
        if (print_flag) printf("Captured %u out of %u bytes: ", pkthdr.caplen, pkthdr.len);

        struct packet_struct parsedPacket;
        unpack_packet(packet, &parsedPacket, pkthdr.caplen);
        // printf("port %d\n", parsedPacket.srcPort);
        if (print_flag) {
            printf("ts: %ld.%ld src ip: %u.%u.%u.%u, dst ip: %u.%u.%u.%u\n", 
                    pkthdr.ts.tv_sec,
                    pkthdr.ts.tv_usec,
                    parsedPacket.srcIpQ1, 
                    parsedPacket.srcIpQ2,
                    parsedPacket.srcIpQ3,
                    parsedPacket.srcIpQ4, 
                    parsedPacket.dstIpQ1,
                    parsedPacket.dstIpQ2,
                    parsedPacket.dstIpQ3,
                    parsedPacket.dstIpQ4);
        }

    }

    pcap_close(infile);
    // pcap_dump_close(outfile);

    return 0;
}
