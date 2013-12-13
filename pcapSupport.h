#ifndef __PCAPSUPPORT_H__
#define __PCAPSUPPORT_H__

#include <pcap.h>
#include <sys/types.h>

#include "constants.h"

/* From RFC 791:
    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   From RFC 793:
    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   From RFC 768:
                  0      7 8     15 16    23 24    31  
                 +--------+--------+--------+--------+ 
                 |     Source      |   Destination   | 
                 |      Port       |      Port       | 
                 +--------+--------+--------+--------+ 
                 |                 |                 | 
                 |     Length      |    Checksum     | 
                 +--------+--------+--------+--------+ 
                 |                                     
                 |          data octets ...            
                 +---------------- ...                 

   ICMP Has constantly changing headers. The only consistant word is:
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   For the rest, see RFC 792.

*/
/* 450805d4585a40002e06c11a437f74e040053543cf2000de1b80e5a1904bbf468010ffff84000000
   +++++--++--+++-++++++--++------++------++--++--++------++------+||||+--+|--||--|
   VIToLen  id FOffTtPrXsum srcIP   dstIP  sPrtdPrt seqNum  ackNum HRFlWin XsumUrg
*/
struct packet_struct 
{
    /* Ethernet frame header */
    u_char dstMacAddr[6];
    u_char srcMacAddr[6];
    u_char etherProto[2];
    /* IP Header */
    u_char ipVer;
    u_char ipHdrLen;
    u_char tos;
    u_int16_t packetLen;
    u_int16_t id;
    u_char flags;
    u_int16_t fragOffset;
    u_char ttl;
    u_char protocol;
    u_int16_t hdrXsum;
    u_char srcIpQ1;
    u_char srcIpQ2;
    u_char srcIpQ3;
    u_char srcIpQ4;
    u_char dstIpQ1;
    u_char dstIpQ2;
    u_char dstIpQ3;
    u_char dstIpQ4;
    u_char* ipOpts;
    /* TCP Header */
    u_int16_t srcPort; /* Also UDP */
    u_int16_t dstPort; /* Also UDP */
    u_int32_t seqNum;
    u_int32_t ackNum;
    u_char tcpHdrLen; /* This is the number of words in the TCP portion of the header. */
    u_char urg;
    u_char ack;
    u_char psh;
    u_char rst;
    u_char syn;
    u_char fin;
    u_int16_t tcpWindow;
    u_int16_t xsum;
    u_int16_t urgPtr;
    u_char* tcpOpts;
    /* UDP Header */
    u_int16_t udpDatLen;
    /* ICMP Header */
    u_char icmpType;
    u_char icmpCode;
    u_int16_t icmpDataLen;
    u_char* icmpData;
    /* Whatever is left is data, which we discard */
};

/* Set the pcap Device Link Type (DLT) so that we know
   how large the link layer header is. This has the
   unfortunate consequence of pretty much requiring the
   use of only one link type in any code that utilizes
   this library. */
void set_link_type(const int dlt);

u_int get_link_hdr_len();

/* parsedPacket should already be allocated */
/* This function will allocate some memory which should be freed by
   calling free_parsed_packet() when you're done with the struct */
void unpack_packet(const u_char* origPacket, struct packet_struct* parsedPacket, 
                   size_t capturedSize);

unsigned int get_packet_hdr_len(const struct packet_struct* parsedPacket);

u_char* alloc_packed_packet(const struct packet_struct* parsedPacket);

/* Use this to free the memory allocated by alloc_packed_packet */
void free_packed_packet(u_char* packedPacket);

/* Use this to free the memory allocated by unpack_packet */
void free_parsed_packet(struct packet_struct* parsedPacket);

/* newPacket should be allocated by the alloc_packed_packet function and
   freed with the free_packed_packet function */
void pack_packet(const struct packet_struct* parsedPacket, u_char* newPacket);

void print_packet(const struct packet_struct* parsedPacket);

/* Write the given parsed packet out to the given pcap dump file and free
   the structures used within that parsed packet */
void writeFreeParsedPacket(struct packet_struct* parsedPacket, pcap_dumper_t* outfile, struct pcap_pkthdr* pkthdr);

#endif /* __PCAPSUPPORT_H__ */
