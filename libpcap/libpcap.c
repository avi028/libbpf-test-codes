#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>

int main(int argc, char const *argv[])
{
	char *device;
	char error_buffer [PCAP_ERRBUF_SIZE];

	device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }
    printf("INFO\t:\tNetwork device found: %s\n", device);

    bpf_u_int32 ip;
    bpf_u_int32 ip_mask;
    int status = pcap_lookupnet(device, &ip, &ip_mask , error_buffer);

    if(status==PCAP_ERROR){
    	printf("ERROR\t:\t%s\n",error_buffer);
    	return 1;
    } 

    struct in_addr address;
	char ip_address[13];

    address.s_addr = ip;

	char * copy_status  = strcpy(ip_address , inet_ntoa(address));
	if(copy_status == NULL) {
		perror("inet_ntoa");
		return 1;
	}   

    printf("INFO\t:\tNetwork Address: %s\n", ip_address);

    pcap_t * handle;

    int max_pkt_len = BUFSIZ;

    int timeout = 1000000; /*in millisec*/

    int pronmiscuous_mode_state = 0; /*need insight*/

    /*open the device for live packet capture */

	printf("INFO\t:\tpaket buffer len %d\n",BUFSIZ);

    handle = pcap_open_live(device,max_pkt_len,pronmiscuous_mode_state,timeout,error_buffer);
    if(handle == NULL){
    	perror("pcap open live failed");
    	return 1;
    }

	printf("INFO\t:\topen live done\n");

	const u_char *packet;
    struct pcap_pkthdr packet_header;
	
    packet  = pcap_next(handle , & packet_header);
    if(packet == NULL){
    	perror("pcak next");
    	return 1;
    }
	printf("INFO\t:\tpcap next success\n");

	printf("INFO\t:\tcaptured packet len%d , packet actual len %d\n",packet_header.caplen,packet_header.len);


	return 0;
}
