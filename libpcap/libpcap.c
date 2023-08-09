#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>

#define DEFAULT_TIMEOUT 1000000 

static volatile bool exiting = false;
pcap_t * handle;

void signal_handle(int sig){
	exiting = true;
	pcap_close(handle);
}

int process_packet(pcap_t * handle){

	const u_char *packet;
    struct pcap_pkthdr packet_header;

    packet  = pcap_next(handle , & packet_header);

    if(packet == NULL){
    	perror("pcak next");
    	return ;
    }

	printf("INFO\t:\tpcap next success\n");
	printf("INFO\t:\tcaptured packet len %d , packet actual len %d\n",packet_header.caplen,packet_header.len);		

	struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
	
	if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
    	printf("Not an IP packet. Skipping...\n\n");
    	return;
	}


	const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    /* Find start of IP header */
    ip_header = packet + ethernet_header_length;
    /* The second-half of the first byte in ip_header contains 
    the IP header length (IHL). */
    ip_header_length = ((*ip_header) & 0x0F);
    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    ip_header_length = ip_header_length << 2;

    /* Now that we know where the IP header is, we can 
       inspect the IP header for a protocol number to 
       make sure it is TCP before going any further. 
       Protocol is always the 10th byte of the IP header */

    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP || protocol != IPPROTO_UDP) {
        printf("INFO\t:\tNot a TCP or UDP packet. Skipping...\n\n");
        return;
    }

    tcp_header = packet + ethernet_header_length + ip_header_length;


    int src_port = *(int*)tcp_header;
    /* TCP header length is stored in the first half 
       of the 12th byte in the TCP header. Because we only want
       the value of the top half of the byte, we have to shift it
       down to the bottom half otherwise it is using the most 
       significant bits instead of the least significant bits */
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    /* The TCP header length stored in those 4 bits represents
       how many 32-bit words there are in the header, just like
       the IP header length. We multiply by four again to get a
       byte count. */
    tcp_header_length = tcp_header_length << 2;	

    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;

    printf("Total header %d bytes\n", total_headers_size);

    payload_length = header->caplen - total_headers_size;

    printf("Payload size: %d bytes\n", payload_length);

    payload = packet + total_headers_size;

    printf("Memory address where payload begins: %p\n\n", payload);

    /* Print payload in ASCII */
    /*  
    if (payload_length > 0) {
        const u_char *temp_pointer = payload;
        int byte_count = 0;
        while (byte_count++ < payload_length) {
            printf("%c", *temp_pointer);
            temp_pointer++;
        }
        printf("\n");
    }
    */
}

int main(int argc, char const *argv[])
{
	signal(SIGINT,signal_handle);
	signal(SIGTERM,signal_handle);

    int max_pkt_len = BUFSIZ;
    int timeout = DEFAULT_TIMEOUT; /*in millisec*/
    int pronmiscuous_mode_state = 0; /*need insight*/

	char *device = "enp2s0";
	char error_buffer [PCAP_ERRBUF_SIZE];

	for(int i = 0 ;i<argc ; i++) {
		if(strcmp (argv[i],"-t")==0){
			i++;
			timeout = atoi(argv[i]);
		}

		else if(strcmp (argv[i],"-d")==0){
			i++;
			device = argv[i];
		}
	}

    printf("INFO\t:\tMonitoring device %s\n", device);


    bpf_u_int32 ip;
    bpf_u_int32 ip_mask;
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


	while(!exiting){
		process_packet(handle);
	}	

	pcap_close(handle);

	return 0;
}
