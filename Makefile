CC=gcc
:w
CPP=g++
#  CFLAGS=-Wall -I/usr/sww/include -L/usr/sww/lib -lpcap -lsocket -lnsl
#  CFLAGS=-Wall -D E_TCP -D E_UDP -D E_ICMP -D E_IP
CFLAGS=-Wall -D E_TCP -D E_UDP -D E_ICMP
LIBS=-lpcap

#  packet_parser: packet_parser.c
#      ${CC} packet_parser.c ${CFLAGS} -o packet_parser ${LIBS}

pcap2sigs: pcap2sigs.o pcapSupport.o
	${CPP} pcap2sigs.o pcapSupport.o ${CFLAGS} -o pcap2sigs ${LIBS}

pcap2sigs.o: pcap2sigs.cc
	${CPP} -c pcap2sigs.cc ${CFLAGS}
pcapSupport.o: pcapSupport.c
	${CC} -c pcapSupport.c

clean:
	rm -f pcap2sigs pcap2sigs.o pcapSupport.o
