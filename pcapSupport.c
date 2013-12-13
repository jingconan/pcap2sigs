#include <string.h> /* For memcpy(3) */
#include <stdio.h>
#include <stdlib.h> /* For malloc(3), free(3) */

#include <pcap.h>
#include "constants.h"
#include "pcapSupport.h"

/* This gets used throughout the file, and we only want to set it
   once, instead of passing it around everywhere.
   Assume Ethernet. */
u_int link_hdr_len = 14;

void set_link_type(const int dlt) 
{
    switch (dlt) {
    case DLT_EN10MB:
        link_hdr_len = 14;
        break;
    case DLT_NULL:
    case DLT_LOOP:
        link_hdr_len = 4;
        break;
    case DLT_RAW:
        link_hdr_len = 0;
        break;
    default:
        link_hdr_len = 0;
        fprintf(stderr, "Warning: Link type %s not recognized.\n", pcap_datalink_val_to_name(dlt));
        /* This includes the link types we don't know the 
           length of and don't expect to encounter. */
    }
}

u_int get_link_hdr_len() 
{
    return link_hdr_len;
}

/* Based on code from http://en.wikipedia.org/wiki/Endianness */
int isBigEndian()
{
   long int i = 1;
   const char *p = (const char *) &i;
   if (p[0] == 1)  // Lowest address contains the least significant byte
      return 0;
   else
      return 1;
}

/* parsedPacket should already be allocated */
/* This function will allocate some memory which should be freed by
   calling free_parsed_packet() when you're done with the struct */
void unpack_packet(const u_char* origPacket, struct packet_struct* parsedPacket, 
                   size_t capturedSize) 
{
    u_char icmpIpHdrOct=0;
    u_char icmpIpHdrProto=0;
    u_char icmpTcpHdrOct=0;
    memcpy((void*)(&(parsedPacket->dstMacAddr[0])), (const void*)origPacket, (size_t)link_hdr_len);
/*    if ( (parsedPacket->etherProto[0] != 0x08) || (parsedPacket->etherProto[1] != 0x00) ) {
        fprintf(stderr, "Error: This program only accepts dumps containing only IPv4 traffic!\n");
        exit(-4);
        }*/
    const u_char* origIpPacket = origPacket+link_hdr_len;
    parsedPacket->ipVer = origIpPacket[0]>>4;    
    parsedPacket->ipHdrLen = origIpPacket[0]&0x0f;
    parsedPacket->tos = origIpPacket[1];
    parsedPacket->packetLen = *((u_int16_t*)(origIpPacket+2)); // TODO: endianness?
    parsedPacket->id = *((u_int16_t*)(origIpPacket+4)); // TODO: endianness?
    if (isBigEndian()) {
        parsedPacket->flags = origIpPacket[6]>>5;
        parsedPacket->fragOffset = (*((u_int16_t*)(origIpPacket+6)))&0x1fff;
    } else {
        parsedPacket->flags = origIpPacket[6]&0x07;
        parsedPacket->fragOffset = (*((u_int16_t*)(origIpPacket+6)))&0xf8ff;
    }
    memcpy(&(parsedPacket->ttl), origIpPacket+8, 12);
    parsedPacket->ipOpts = 0;
    unsigned int ipOptsLen = 0;
    if (parsedPacket->ipHdrLen>5) {
        ipOptsLen = 4 * ((parsedPacket->ipHdrLen)-5);
        parsedPacket->ipOpts = malloc( ipOptsLen );
        memcpy(parsedPacket->ipOpts, origIpPacket+20, ipOptsLen);
    }
    const u_char* origProtoPacket= origIpPacket+20+ipOptsLen;
    switch(parsedPacket->protocol) {
    case 1: /* ICMP */
        parsedPacket->icmpType = *(origProtoPacket);
        parsedPacket->icmpCode = *(origProtoPacket+1);
        parsedPacket->xsum = *((u_int16_t*)(origProtoPacket+2)); // TODO: endianness?
        switch (parsedPacket->icmpType) {
        case 3: /* Destination unreachable */
        case 11: /* Time exceeded */
        case 12: /* Parameter problem */
        case 4: /* Source quench */
        case 5: /* Redirect message */
            icmpIpHdrOct = (*(origProtoPacket+8))&0x0f;
            icmpIpHdrProto = (*(origProtoPacket+17))&0x0f;
            parsedPacket->icmpDataLen = icmpIpHdrOct*4;
            parsedPacket->icmpDataLen += 4; /* One word before */
            /* While the ICMP spec only guarentees 8 bytes after the IP header, in practice
               the entire packet is returned, so we'll grab as much of any session layer
               protocol headers as possible, otherwise we'll default to the guarenteed
               8 bytes. If this assumption doesn't hold, we'll automatically be scaled
               down in size below. */
            switch (icmpIpHdrProto) {
            case 6: /* TCP */
                icmpTcpHdrOct = (*(origProtoPacket+4+parsedPacket->icmpDataLen+12))>>4;
                parsedPacket->icmpDataLen += icmpTcpHdrOct*4;
                break;
            case 1: /* ICMP -- use default */
            case 17: /* UDP -- use default */
            default:
                parsedPacket->icmpDataLen += 8; /* And 64-bits after */
                break;
            }
            break;
        case 0: /* ICMP echo reply */
        case 8: /* ICMP echo */
            parsedPacket->icmpDataLen = parsedPacket->packetLen-(parsedPacket->ipHdrLen*4+4);
            break;
        case 13: /* Timestamp message */
        case 14: /* Timestamp reply */
            parsedPacket->icmpDataLen = 16;
            break;
        case 15: /* Information request */
        case 16: /* Information reply */ 
            parsedPacket->icmpDataLen = 4;
            break;
        default: /* Unknown ICMP type */
            parsedPacket->icmpDataLen = 0;
            break;
        }
        /* If the ICMP data extends beyond what we captured, correct the length */
        if (parsedPacket->icmpDataLen+38+ipOptsLen > capturedSize) {
            parsedPacket->icmpDataLen = capturedSize - (38+ipOptsLen);
        }
        parsedPacket->icmpData = malloc( parsedPacket->icmpDataLen );
        memcpy(parsedPacket->icmpData, origProtoPacket+4, parsedPacket->icmpDataLen);
        break;
    case 6: /* TCP */
        parsedPacket->srcPort = *((u_int16_t*)(origProtoPacket)); // TODO: endianness?
        parsedPacket->dstPort = *((u_int16_t*)(origProtoPacket+2)); // TODO: endianness?
        parsedPacket->seqNum = *((u_int32_t*)(origProtoPacket+4)); // TODO: endianness?
        parsedPacket->ackNum = *((u_int32_t*)(origProtoPacket+8)); // TODO: endianness?
        parsedPacket->tcpHdrLen = *(origProtoPacket+12)>>4;
        parsedPacket->urg = *(origProtoPacket+13)&0x20;
        parsedPacket->ack = *(origProtoPacket+13)&0x10;
        parsedPacket->psh = *(origProtoPacket+13)&0x08;
        parsedPacket->rst = *(origProtoPacket+13)&0x04;
        parsedPacket->syn = *(origProtoPacket+13)&0x02;
        parsedPacket->fin = *(origProtoPacket+13)&0x01;
        parsedPacket->tcpWindow = *((u_int16_t*)(origProtoPacket+14)); // TODO: endianness?
        parsedPacket->xsum = *((u_int16_t*)(origProtoPacket+16)); // TODO: endianness?
        parsedPacket->urgPtr = *((u_int16_t*)(origProtoPacket+18)); // TODO: endianness?
        parsedPacket->tcpOpts = 0;
        unsigned int tcpOptsLen = 0;
        if (parsedPacket->tcpHdrLen>5) {
            tcpOptsLen = 4 * ((parsedPacket->tcpHdrLen)-5);
            parsedPacket->tcpOpts = malloc( tcpOptsLen );
            memcpy(parsedPacket->tcpOpts, origProtoPacket+20, tcpOptsLen);
        }
        break;
    case 17: /* UDP */
        parsedPacket->srcPort = *((u_int16_t*)(origProtoPacket)); // TODO: endianness?
        parsedPacket->dstPort = *((u_int16_t*)(origProtoPacket+2)); // TODO: endianness?
        parsedPacket->udpDatLen = *((u_int16_t*)(origProtoPacket+4)); // TODO: endianness?
        parsedPacket->xsum = *((u_int16_t*)(origProtoPacket+6)); // TODO: endianness?
        break;
    }
    
}

unsigned int get_packet_hdr_len(const struct packet_struct* parsedPacket) 
{
    unsigned int packetLen = link_hdr_len+(parsedPacket->ipHdrLen*4);
    switch (parsedPacket->protocol) {
    case 1:
        packetLen += 4 + parsedPacket->icmpDataLen;
        break;
    case 6:
        packetLen += parsedPacket->tcpHdrLen*4;
        break;
    case 17:
        packetLen += 8;
        break;
    }
    return packetLen;
}

u_char* alloc_packed_packet(const struct packet_struct* parsedPacket) 
{
    unsigned int pkt_hdr_len = get_packet_hdr_len(parsedPacket);
    u_char* ret = malloc(pkt_hdr_len);
    return ret;
}

void free_packed_packet(u_char* packedPacket) 
{
    free( packedPacket );
}

void free_parsed_packet(struct packet_struct* parsedPacket) 
{
    if (parsedPacket->ipHdrLen>5) {
        free( parsedPacket->ipOpts );
        parsedPacket->ipOpts = 0;
    }
    switch (parsedPacket->protocol) {
    case 1:
        free( parsedPacket->icmpData );
        parsedPacket->icmpData = 0;
        break;
    case 6:
        if (parsedPacket->tcpHdrLen>5) {
            free( parsedPacket->tcpOpts );
            parsedPacket->tcpOpts = 0;
        }
        break;
    }
}

// TODO: endianness?
void set_iph_xsum(const struct packet_struct* parsedPacket, u_char* newPacket) 
{
    /* Compute the new checksum
       Based on code from http://www.netfor2.com/ipsum.htm
       Set the checksum to zero, sum up the two-byte ints,
       add the lower and upper 16-bits, and find the one's complement. */
    newPacket[link_hdr_len+10] = 0;
    newPacket[link_hdr_len+11] = 0;
    u_int16_t shortWord = 0;
    unsigned int sum = 0;
    int lcv;
    for (lcv=link_hdr_len; lcv<link_hdr_len+parsedPacket->ipHdrLen*4; lcv+=2) {
        shortWord = ((newPacket[lcv]<<8)&0xff00)+(newPacket[lcv+1]&0x00ff);
        sum += shortWord;
    }
    while (sum>>16) {
        sum = (sum & 0xffff)+(sum>>16);
    }
    sum = ~sum;
    newPacket[link_hdr_len+10] = sum>>8;
    newPacket[link_hdr_len+11] = sum&0x00ff;
}

/* newPacket should be allocated by the alloc_packed_packet function and
   freed with the free_packed_packet function */
void pack_packet(const struct packet_struct* parsedPacket, u_char* newPacket) 
{
    memcpy(newPacket, parsedPacket->dstMacAddr, link_hdr_len);
    u_char* newIpPacket = newPacket+link_hdr_len;
    newIpPacket[0] = ((parsedPacket->ipVer)<<4)|(parsedPacket->ipHdrLen);
    newIpPacket[1] = parsedPacket->tos;
    *((u_int16_t*)(newIpPacket+2)) = parsedPacket->packetLen;
    *((u_int16_t*)(newIpPacket+4)) = parsedPacket->id;
    if (isBigEndian()) {
        *((u_int16_t*)(newIpPacket+6)) = ((parsedPacket->flags)<<13)|(parsedPacket->fragOffset);
    } else {
        *((u_int16_t*)(newIpPacket+6)) = ((parsedPacket->flags)<<8)|(parsedPacket->fragOffset);
    }
    memcpy(newIpPacket+8, &(parsedPacket->ttl), 12);
    unsigned int ipOptsLen = 0;
    if (parsedPacket->ipHdrLen>5) {
        ipOptsLen = 4 * ((parsedPacket->ipHdrLen)-5);
        memcpy(newIpPacket+20, parsedPacket->ipOpts, ipOptsLen);
    }
    u_char* newProtoPacket = newIpPacket+20+ipOptsLen;
    switch (parsedPacket->protocol) {
    case 1:
        *(newProtoPacket) = parsedPacket->icmpType;
        *(newProtoPacket+1) = parsedPacket->icmpCode;
        *((u_int16_t*)(newProtoPacket+2)) = parsedPacket->xsum;
        memcpy(newProtoPacket+4, parsedPacket->icmpData, parsedPacket->icmpDataLen);
        break;
    case 6:
        *((u_int16_t*)(newProtoPacket)) = parsedPacket->srcPort;
        *((u_int16_t*)(newProtoPacket+2)) = parsedPacket->dstPort;
        *((u_int32_t*)(newProtoPacket+4)) = parsedPacket->seqNum;
        *((u_int32_t*)(newProtoPacket+8)) = parsedPacket->ackNum;
        *(newProtoPacket+12) = parsedPacket->tcpHdrLen<<4;
        u_char flags = 0;
        if (parsedPacket->urg) flags = flags|0x20;
        if (parsedPacket->ack) flags = flags|0x10;
        if (parsedPacket->psh) flags = flags|0x08;
        if (parsedPacket->rst) flags = flags|0x04;
        if (parsedPacket->syn) flags = flags|0x02;
        if (parsedPacket->fin) flags = flags|0x01;
        *(newProtoPacket+13) = flags;
        *((u_int16_t*)(newProtoPacket+14)) = parsedPacket->tcpWindow;
        *((u_int16_t*)(newProtoPacket+16)) = parsedPacket->xsum;
        *((u_int16_t*)(newProtoPacket+18)) = parsedPacket->urgPtr;
        unsigned int tcpOptsLen = 0;
        if (parsedPacket->tcpHdrLen>5) {
            tcpOptsLen = 4 * ((parsedPacket->tcpHdrLen)-5);
            memcpy(newProtoPacket+20, parsedPacket->tcpOpts, tcpOptsLen);
        }
        break;
    case 17:
        *((u_int16_t*)(newProtoPacket)) = parsedPacket->srcPort;
        *((u_int16_t*)(newProtoPacket+2)) = parsedPacket->dstPort;
        *((u_int16_t*)(newProtoPacket+4)) = parsedPacket->udpDatLen;
        *((u_int16_t*)(newProtoPacket+6)) = parsedPacket->xsum;
        break;
    }
    /* Fix the IP header checksum */
    set_iph_xsum(parsedPacket, newPacket);
}

void print_packet(const struct packet_struct* parsedPacket) 
{
    if (link_hdr_len == 14) {
        int lcv=0;
        for (lcv=0; lcv<6; lcv++) {
            printf("%02x", parsedPacket->srcMacAddr[lcv]);
            if (lcv<5) printf(":");
        }
        printf(" > ");
        for (lcv=0; lcv<6; lcv++) {
            printf("%02x", parsedPacket->dstMacAddr[lcv]);
            if (lcv<5) printf(":");
        }
        printf(", ethertype (0x%02x%02x), ", parsedPacket->etherProto[0], parsedPacket->etherProto[1]);
    }
    
    printf("ipver: %u, hdrlen: %u, tos: %u, len: %u, id: %u, flags: %02x, off: %u, ttl: %u, proto: %u, xsum: 0x%04x, ", parsedPacket->ipVer, parsedPacket->ipHdrLen, parsedPacket->tos, parsedPacket->packetLen, parsedPacket->id, parsedPacket->flags, parsedPacket->fragOffset, parsedPacket->ttl, parsedPacket->protocol, parsedPacket->hdrXsum);
    switch (parsedPacket->protocol) {
    case 1:
        printf("%u.%u.%u.%u > %u.%u.%u.%u ", parsedPacket->srcIpQ1, parsedPacket->srcIpQ2, parsedPacket->srcIpQ3, parsedPacket->srcIpQ4, parsedPacket->dstIpQ1, parsedPacket->dstIpQ2, parsedPacket->dstIpQ3, parsedPacket->dstIpQ4);
        printf("type: %u, code: %u, xsum: %04x, datlen: %u", parsedPacket->icmpType, parsedPacket->icmpCode, parsedPacket->xsum, parsedPacket->icmpDataLen);
        break;
    case 6:
        printf("%u.%u.%u.%u:%u > %u.%u.%u.%u:%u ", parsedPacket->srcIpQ1, parsedPacket->srcIpQ2, parsedPacket->srcIpQ3, parsedPacket->srcIpQ4, parsedPacket->srcPort, parsedPacket->dstIpQ1, parsedPacket->dstIpQ2, parsedPacket->dstIpQ3, parsedPacket->dstIpQ4, parsedPacket->dstPort);
        printf("seq: %u, ack: %u, tcphdrlen: %u, [", parsedPacket->seqNum, parsedPacket->ackNum, parsedPacket->tcpHdrLen);
        if (parsedPacket->urg) printf("U");
        if (parsedPacket->ack) printf("A");
        if (parsedPacket->psh) printf("P");
        if (parsedPacket->rst) printf("R");
        if (parsedPacket->syn) printf("S");
        if (parsedPacket->fin) printf("F");
        printf("] win: %u, xsum: %04x, uptr: %04x", parsedPacket->tcpWindow, parsedPacket->xsum, parsedPacket->urgPtr);
        break;
    case 17:
        printf("%u.%u.%u.%u:%u > %u.%u.%u.%u:%u ", parsedPacket->srcIpQ1, parsedPacket->srcIpQ2, parsedPacket->srcIpQ3, parsedPacket->srcIpQ4, parsedPacket->srcPort, parsedPacket->dstIpQ1, parsedPacket->dstIpQ2, parsedPacket->dstIpQ3, parsedPacket->dstIpQ4, parsedPacket->dstPort);
        printf("datlen: %u, xsum: %04x", parsedPacket->udpDatLen, parsedPacket->xsum);
        break;
    default:
        printf("%u.%u.%u.%u > %u.%u.%u.%u ", parsedPacket->srcIpQ1, parsedPacket->srcIpQ2, parsedPacket->srcIpQ3, parsedPacket->srcIpQ4, parsedPacket->dstIpQ1, parsedPacket->dstIpQ2, parsedPacket->dstIpQ3, parsedPacket->dstIpQ4);
        break;
    }
    printf("\n");
}

/* Write the given parsed packet out to the given pcap dump file and free
   the structures used within that parsed packet */
void writeFreeParsedPacket(struct packet_struct* parsedPacket, pcap_dumper_t* outfile, struct pcap_pkthdr* pkthdr) 
{
    u_char* newPacket = alloc_packed_packet(parsedPacket);
    pack_packet(parsedPacket, newPacket);
    pkthdr->caplen=get_packet_hdr_len(parsedPacket);
    pcap_dump((u_char*)outfile, pkthdr, newPacket);
    free_packed_packet(newPacket);
    free_parsed_packet(parsedPacket);
}
