#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_ether.h>

// user defined #def

#define DEFAULT_TIMEOUT 1000000 
#define DEBUG_LEVEL_2 0
#define DEBUG_LEVEL_1 0
#define MIN_HTTP_HEADER 50
#define DEFAULT_PORT 80

#define NOT_HTTP 0
#define HTTP_RESPONSE 1
#define GET_REQUEST 2
#define POST_REQUEST 3


struct p_data{
    char load[MIN_HTTP_HEADER];
};

struct char500{
    char c[1500];
};

static volatile bool exiting = false;
pcap_t * handle;

void signal_handle(int sig){
	exiting = true;
	pcap_close(handle);
}

static inline struct ip * is_ip(struct ethhdr *eth_hdr,void * payload , int len){
    struct ip *ip_hdr = NULL;

    // Null check
    if(!eth_hdr ||  !payload)
        return NULL;

    //size check
    if(sizeof(*eth_hdr) + sizeof(*ip_hdr) > len)
        return NULL;

    if(eth_hdr->h_proto == htons(ETH_P_IP))
        ip_hdr = (struct ip *)((void*)eth_hdr + sizeof(*eth_hdr));

    return ip_hdr;
}


static inline struct tcphdr * is_tcp(struct ip * ip_hdr  ,void * payload , int len){
    struct tcphdr * tcp_hdr = NULL;

    if(!ip_hdr || !payload)
        return NULL;

    // minimum IP header length check
    int ip_len = (ip_hdr->ip_hl<<2);
    if( ip_len < sizeof(*ip_hdr))
        return NULL;

    if(ip_hdr)  
        if( ip_len + sizeof(*tcp_hdr) > len)
            return NULL;

    if(ip_hdr->ip_p == IPPROTO_TCP)
        tcp_hdr = (struct tcphdr*)((void *)ip_hdr + ip_len);

    return tcp_hdr;
}

static inline struct udphdr * is_udp(struct ip * ip_hdr  ,void * payload , int len){
    struct udphdr * hdr = NULL;

    if(!ip_hdr || !payload)
        return NULL;

    // minimum IP header length check
    int ip_len = (ip_hdr->ip_hl<<2);
    if( ip_len < sizeof(*ip_hdr))
        return NULL;

    if(ip_hdr)  
        if( ip_len + sizeof(*hdr) > len)
            return NULL;

    if(ip_hdr->ip_p == IPPROTO_UDP)
        hdr = (struct udphdr*)((void *)ip_hdr + ip_len);

    return hdr;
}

static inline int is_http(void * payload,int payload_offset , int len){

    struct p_data * http_header = NULL;

    if(!payload)
        return 0;

    if(payload_offset + sizeof(*http_header) > len)
        return -1;

    http_header = (struct p_data * )((void *)payload + payload_offset);
    
    if(http_header->load[0]=='H' && http_header->load[1]=='T' && http_header->load[2]=='T' && http_header->load[3]=='P')
        return HTTP_RESPONSE;

    if(http_header->load[0]=='G' && http_header->load[1]=='E' && http_header->load[2]=='T')
        return GET_REQUEST;        

    if(http_header->load[0]=='P' && http_header->load[1]=='O' && http_header->load[2]=='S' && http_header->load[3]=='T')        
        return POST_REQUEST;

    return -2;
}


int process_packet(pcap_t * handle){

	const u_char *packet;
    struct pcap_pkthdr packet_header;

    packet  = pcap_next(handle , & packet_header);

    if(packet == NULL){
    	perror("pcak next");
    	return 0;
    }
    int pkt_len = packet_header.caplen;

if(DEBUG_LEVEL_2)	printf("INFO\t:\tpcap next success\n");
if(DEBUG_LEVEL_2)	printf("INFO\t:\tcaptured packet len %d , packet actual len %d\n",pkt_len,packet_header.len);		

	struct ethhdr * eth_hdr = (void*) packet;
    int eth_hdr_len = sizeof(struct ethhdr);

	// IP Filter
	struct ip * ip_hdr = is_ip(eth_hdr,(void*)packet,pkt_len);

    if(!ip_hdr){
        if(DEBUG_LEVEL_2) printf("IP FILTER\n");
        return 0;
    }

    int ip_hdr_len      =   (ip_hdr->ip_hl<<2);
    __u16 total_pkt_len =   ntohs(ip_hdr->ip_len);

    // TCP/UDP Filter
    int src_port        =   0;    
    int dest_port       =   0;     
    int tl_hdr_len      =   0;        

    if(ip_hdr->ip_p == IPPROTO_TCP){
		if(DEBUG_LEVEL_2)    	printf("TCP\n");
	    struct tcphdr * hdr = is_tcp(ip_hdr,(void*)packet,pkt_len);
    	src_port = ntohs(hdr->source);
    	dest_port = ntohs(hdr->dest);
	    tl_hdr_len  =   (hdr->doff<<2);    
	}

	else if(ip_hdr->ip_p == IPPROTO_UDP){
		if(DEBUG_LEVEL_2)    	printf("UDP\n");
	    struct udphdr * hdr = is_udp(ip_hdr,(void*)packet,pkt_len);
    	src_port = ntohs(hdr->source);
    	dest_port = ntohs(hdr->dest);
        tl_hdr_len  =   sizeof(*hdr);    
	}
	else{
		return 0;
	}

	//Port Filter
	if(src_port != DEFAULT_PORT && dest_port!=DEFAULT_PORT){
		if(DEBUG_LEVEL_2)printf("PORT FILTER\n");						
		return 0;
	}

	if(DEBUG_LEVEL_2)	printf("src port: %d , dest port: %d\n",src_port,dest_port);

	// HTTP len Filter
	int payload_offset = eth_hdr_len + ip_hdr_len + tl_hdr_len;

	if(payload_offset + MIN_HTTP_HEADER > pkt_len){
		if(DEBUG_LEVEL_1)printf("HTTP LEN FILTER\n");				
		return 0;
	}

	int status  = is_http((void*)packet,payload_offset,pkt_len);

	if(status == HTTP_RESPONSE){	
		struct char500 * c_ptr = (struct char500*)((void*) packet + payload_offset);
		if(DEBUG_LEVEL_1) printf("Payload \n -----------------\n%s\n-----------------------\n ",c_ptr->c);

	    int i=0;
	    int flag=0;

	    for(i=0;flag == 0 && i<(sizeof(*c_ptr)-4);i++){
	        if(flag==0 && c_ptr->c[i]=='\r' && c_ptr->c[i+1]=='\n' && c_ptr->c[i+2]=='\r' && c_ptr->c[i+3]=='\n'){
	            i = i+4;
	            flag=1;
	        }
	    }

	    for( ;flag ==1 && i<sizeof(*c_ptr);i++){
	        if(c_ptr->c[i]=='1' && i == sizeof(*c_ptr)-1){
	            flag=-1;
	        }
	    }

	    if(flag== -1){
	    	return 1;
	    }
	}

    return 0;
 }

int main(int argc, char const *argv[])
{
	signal(SIGINT,signal_handle);
	signal(SIGTERM,signal_handle);

    int max_pkt_len = BUFSIZ;
    int timeout = DEFAULT_TIMEOUT; /*in millisec*/
    int pronmiscuous_mode_state = 0; /*need insight*/

	char device [] = "enp2s0";
	char error_buffer [PCAP_ERRBUF_SIZE];

	for(int i = 0 ;i<argc ; i++) 
		printf("argv[%d] : %s\n",i,argv[i]);

	for(int i = 0 ;i<argc ; i++) {
		if(strcmp (argv[i],"-t")==0){
			i++;
			timeout = atoi(argv[i]);
		}

		else if(strcmp (argv[i],"-d")==0){
			i++;
			strcpy(device,argv[i]);
		}
	}

    printf("INFO\t:\tMonitoring device %s\n", device);

    bpf_u_int32 ip;
    struct in_addr address;
	char ip_address[15];

    address.s_addr = ip;
	char * copy_status  = strcpy(ip_address , inet_ntoa(address));
	if(copy_status == NULL) {
		perror("inet_ntoa");
		return 1;
	}   

    printf("INFO\t:\tNetwork Address: %s\n", ip_address);
	printf("INFO\t:\tpaket buffer len %d\n",BUFSIZ);

    /*open the device for live packet capture */
    handle = pcap_open_live(device,max_pkt_len,pronmiscuous_mode_state,timeout,error_buffer);
    if(handle == NULL){
    	perror("pcap open live failed");
    	return 1;
    }

	printf("INFO\t:\topen live done\n");

	int count=0;
	while(!exiting){
		int tmp =process_packet(handle);
		if(tmp ==1){
			count+=tmp;
	        printf("200 Status Count: %d\r",count);
	        fflush(stdout);			
		}
	}	

	return 0;
}
