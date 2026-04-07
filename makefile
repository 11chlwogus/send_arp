LDLIBS += -lpcap

all: send-arp

send-arp: send-arp.c
	g++ -o send-arp send-arp.c -lpcap

clean:
	rm -f send-arp
