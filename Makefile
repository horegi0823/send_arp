all:send_arp

send_arp: send_arp.o
	gcc -o send_arp send_arp.o -lpcap

send_arp.o:
	gcc -c -o send_arp.o send_arp.c

clean:
	rm -f *.o
	rm -f send_arp

