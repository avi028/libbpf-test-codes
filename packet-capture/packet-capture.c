/**********************************************************************
* file:   testpcap2.c
* date:   2001-Mar-14 12:14:19 AM 
* Author: Martin Casado
* Last Modified:2001-Mar-14 12:14:11 AM
*
* Description: Q&D proggy to demonstrate the use of pcap_loop
*
**********************************************************************/

#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// #include <netinet/ether.h>
// #include <netinet/ip.h>
// #include <netinet/tcp.h>
// #include <netinet/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdint.h>
#include <errno.h>

#define FILTER "ether proto \\ip and dst host 172.16.10.1 and ip proto \\udp or \\tcp and dst port 5000"
#define TIMEOUT 1000
#define MAX_PARSE_SIZE 1400
#define BUFFSIZE 20971520

#define UDP_HLEN 8

int counter = 0;
pcap_t* descr;

static volatile int exiting = 0;
static void sig_handler(int sig)
{
    exiting = 1;
    pcap_close(descr);
}


/* callback function that is passed to pcap_loop(..) or to process packet_header and called each time 
 * a packet is recieved
                                                     */
void packetparser(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet){
    struct ethhdr *eth_hdr = NULL;     /* linux/if_ether.h */
    struct iphdr *ip_hdr = NULL;       /* linux/ip.h */
    struct tcphdr *tcp_hdr = NULL;     /* linux/tcp.h */
    struct udphdr *udp_hdr = NULL;     /* linux/udp.h */
    u_char *payload = NULL;
    int16_t payload_length;

    eth_hdr = (struct ethhdr *)packet;             
    if(eth_hdr->h_proto != htons(ETH_P_IP)){
        return;
    }

    ip_hdr = (struct iphdr*)(packet+ETH_HLEN);
    uint8_t ip_hlen = ip_hdr->ihl << 2;

    if(ip_hdr->protocol == IPPROTO_TCP){
        tcp_hdr = (struct tcphdr*)(packet+ ETH_HLEN+ ip_hlen);        
    }
    else if(ip_hdr->protocol == IPPROTO_UDP){
        udp_hdr = (struct udphdr*)(packet+ ETH_HLEN+ ip_hlen);        
    }
    else
        return;

    if(tcp_hdr != NULL){
        uint8_t tcp_hlen = tcp_hdr->doff << 2;
        payload = (u_char *)(packet + ETH_HLEN + ip_hlen + tcp_hlen);
        payload_length = payload_length<MAX_PARSE_SIZE? payload_length: MAX_PARSE_SIZE;
    }
    else{
        payload = (u_char *)(packet + ETH_HLEN + ip_hlen + UDP_HLEN);
        payload_length = pkthdr->caplen - (ETH_HLEN + ip_hlen + UDP_HLEN);
        payload_length = payload_length<MAX_PARSE_SIZE? payload_length: MAX_PARSE_SIZE;
    }

	if(payload[0]=='H' && payload[1]=='T' && payload[2]=='T' && payload[3]=='P'){
		int flag = 0 ;	
		int http_header_len = 0;		
		for(int i =0 ;i<payload_length-3;i++){
			http_header_len++;
			if(payload[i]=='\r' && payload[i+1]=='\n' && payload[i+2]=='\r' && payload[i+3]=='\n'){
				flag=1;
				break;
			}
		}
		http_header_len+=3;
		if(flag==1)
			for(int i = http_header_len ; i< payload_length ;i ++){
				// if(payload[i]==1)
					flag=-1;
			}

		if(flag == -1){
			counter++;			
		}
	}

    if((counter & 0x1FFFF) == 0){
        // fprintf(stdout,"\rPayload Length: %010u Number of Packets Received: %d", payload_length, counter);
        fprintf(stdout,"\rNumber of Packets Received: %d", counter);
        fflush(stdout);
    }
}

pcap_t *pcap_open_get_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf, int buffersize){
    pcap_t * p;
    int status;
    p = pcap_create(device, errbuf);
	if (p == NULL)
		return (NULL);
	status = pcap_set_snaplen(p, snaplen);
	if (status < 0)
		return (NULL);
	status = pcap_set_promisc(p, promisc);
	if (status < 0)
		return (NULL);
	status = pcap_set_timeout(p, to_ms);
	if (status < 0)
		return (NULL);

    status = pcap_set_buffer_size(p, buffersize);
    if(status != 0){
        printf("buffer size set to default\n");
    };

    // p->oldstyle = 1;
	status = pcap_activate(p);
	if (status < 0)
		return (NULL);
	return (p);
}


int main(int argc,char **argv)
{ 
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    char *dev = "ens259f0"; 
    char errbuf[PCAP_ERRBUF_SIZE];
    
    struct bpf_program fp;
    char *filter = FILTER;
    bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip                        */

    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */

    // /* grab a device to peak into... */
    // dev = pcap_lookupdev(errbuf);
    // if(dev == NULL)
    // { 
    //     printf("%s\n",errbuf); exit(1); 
    // }
    // else
    //     printf("%s\n", dev);
    /* open device for reading */

    /* ask pcap for the network address and mask of the device */
    pcap_lookupnet(dev, &netp, &maskp, errbuf);
    
    unsigned int snaplen = argc < 2? BUFSIZ: atoi(argv[1]) == 1? MAX_PARSE_SIZE + (ETH_HLEN + 60+ 60): BUFSIZ;
    printf("SnapLen %d\n", snaplen);

    descr = pcap_open_get_live(dev, snaplen, 0, TIMEOUT, errbuf, BUFFSIZE);
    // descr = pcap_open_live(dev, snaplen, 0, TIMEOUT, errbuf);
    if(descr == NULL)
    { printf("pcap_open_live(): %s\n",errbuf); exit(1); }

    // if(pcap_set_buffer_size(descr, BUFFSIZE) != 0){
    //     printf("buffer size set to default\n");
    // };

    /* Lets try and compile the program.. non-optimized */
    if(pcap_compile(descr, &fp, filter, 0, netp) == -1)
    { fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }

    // /* set the compiled program as the filter */
    if(pcap_setfilter(descr, &fp) == -1)
    { fprintf(stderr,"Error setting filter\n"); exit(1); }

    /* allright here we call pcap_loop(..) and pass in our callback function */
    /* int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)*/
    /* If you are wondering what the user argument is all about, so am I!!   */
    while(!exiting){
        packet = pcap_next(descr,&hdr);
        if(packet != NULL)
            packetparser(NULL, &hdr, packet);
    }

    fprintf(stdout,"\rDone processing %d packets... wheew!\n", counter);
    return 0;
}