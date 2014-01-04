#include <string.h> /* For memcpy(3) */
#include <stdio.h>
#include <stdlib.h> /* For malloc(3), free(3) */

#include <pcap.h>
#include "constants.h"
#include "pcapSupport.h"

/* This gets used throughout the file, and we only want to set it
   once, instead of passing it around everywhere.
   Assume Ethernet. */
/* u_int link_hdr_len = 14; */
 /* Assume RAW */
u_int link_hdr_len = 0;

void set_link_type(const int dlt) 
{
    /* cout << "dlt: " << dlt << " DLT_RAW: " << DLT_RAW << endl; */
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

