/*#include <string.h>*/ /* For memcpy(3) */
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h> /* For random(3) */
#include <string.h> /* For strcmp() */
#include <sys/types.h>
#include <inttypes.h>

extern "C" {
#include "constants.h"
#include "pcapSupport.h"
}

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

    // pcap_dumper_t* outfile = pcap_dump_open(infile, argv[2]);
    // if (outfile == null) {
    //     fprintf(stderr, "Unable to open %s: %s", argv[2], pcap_geterr(infile));
    //     return -3;
    // }

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

        if (print_flag) print_packet(&parsedPacket);

        /* Write out the modified packet */
        /* writeFreeParsedPacket(&parsedPacket, outfile, &pkthdr); */
    }

    pcap_close(infile);
    // pcap_dump_close(outfile);

    return 0;
}
