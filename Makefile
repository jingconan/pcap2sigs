CC=g++
#  CFLAGS=-Wall -I/usr/sww/include -L/usr/sww/lib -lpcap -lsocket -lnsl
CFLAGS=-Wall
LIBS=-lpcap

#  packet_parser: packet_parser.c
#      ${CC} packet_parser.c ${CFLAGS} -o packet_parser ${LIBS}

pcap2sigs: pcap2sigs.o pcapSupport.o
	${CC} pcap2sigs.o pcapSupport.o ${CFLAGS} -o pcap2sigs ${LIBS}

pcap2sigs.o: pcap2sigs.cc
pcapSupport.o: pcapSupport.c
	gcc -c pcapSupport.c

clean:
	rm -f pcap2sigs pcap2sigs.o pcapSupport.o
