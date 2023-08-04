#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "tc_perf_ipc.h"

//#include <linux/pkt_cls.h>
#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_OK		0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		2
#define TC_ACT_PIPE		3
#define TC_ACT_STOLEN		4
#define TC_ACT_QUEUED		5
#define TC_ACT_REPEAT		6
#define TC_ACT_REDIRECT		7
#define TC_ACT_TRAP		8

// #def not available in vmlinux.h
#define ETH_P_IP    0x0800

// for easy understanding 
#define htons bpf_htons
#define ntohl bpf_ntohl
#define ntohs bpf_ntohs

// user defined #def
#define DEBUG_LEVEL_2 0
#define DEBUG_LEVEL_1 0
#define MIN_HTTP_HEADER 50
#define PORT_LIST_SIZE 10
#define NOT_HTTP 0
#define HTTP_RESPONSE 1
#define GET_REQUEST 2
#define POST_REQUEST 3

/*## MAPS ##*/

/* BPF perfbuf map */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} pb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct event);
} user_event_data SEC(".maps");

/*## STRUCTS ##*/

struct p_data{
    char load[MIN_HTTP_HEADER];
};

struct char1{
    char c[1];
};

struct char2{
    char c[2];
};

struct char4{
    char c[4];
};

struct char100{
    char c[100];
};

struct char500{
    char c[MAX_SIZE];
};

/*## FUNCTIONS ##*/

static inline struct iphdr * is_ip(struct ethhdr *eth_hdr,void * data_end){
    struct iphdr *ip_hdr = NULL;

    // Null check
    if(!eth_hdr ||  !data_end)
        return NULL;

    //size check
    if((void*) eth_hdr + sizeof(*eth_hdr) + sizeof(*ip_hdr) > data_end)
        return NULL;

    if(eth_hdr->h_proto == htons(ETH_P_IP))
        ip_hdr = (struct iphdr *)((void*)eth_hdr + sizeof(*eth_hdr));

    return ip_hdr;
}

static inline struct tcphdr * is_tcp(struct iphdr * ip_hdr  ,  void * data_end){
    struct tcphdr * tcp_hdr = NULL;

    if(!ip_hdr || !data_end)
        return NULL;

    // minimum IP header length check
    if((ip_hdr->ihl<<2) < sizeof(*ip_hdr))
        return NULL;

    if(ip_hdr)  
        if((void *)ip_hdr + (ip_hdr->ihl<<2) + sizeof(*tcp_hdr) > data_end)
            return NULL;

    if(ip_hdr->protocol == IPPROTO_TCP)
        tcp_hdr = (struct tcphdr*)((void *)ip_hdr + (ip_hdr->ihl<<2));

    return tcp_hdr;
}

static inline struct  udphdr * is_udp(struct iphdr * ip_hdr  ,  void * data_end){
    struct udphdr * udp_hdr = NULL;

    if(!ip_hdr || !data_end)
        return NULL;

    // minimum IP header length check
    if((ip_hdr->ihl<<2) < sizeof(*ip_hdr))
        return NULL;

    if(ip_hdr)  
        if((void *)ip_hdr + (ip_hdr->ihl<<2) + sizeof(*udp_hdr) > data_end)
            return NULL;

    if(ip_hdr->protocol == IPPROTO_UDP)
        udp_hdr = (struct udphdr*)((void *)ip_hdr + (ip_hdr->ihl<<2));

    return udp_hdr;
}


static inline int is_http(struct __sk_buff *skb,int payload_offset){

    struct p_data * payload = NULL;

    if(!skb)
        return 0;

    void *data_end = (void*)(__u64)skb->data_end;
    void *data = (void *)(__u64)skb->data;

    if(((void *)data + payload_offset + sizeof(*payload)) > data_end)
        return -1;

    payload = (struct p_data * )((void *)data + payload_offset);
    
    if(payload->load[0]=='H' && payload->load[1]=='T' && payload->load[2]=='T' && payload->load[3]=='P')
        return HTTP_RESPONSE;

    if(payload->load[0]=='G' && payload->load[1]=='E' && payload->load[2]=='T')
        return GET_REQUEST;        

    if(payload->load[0]=='P' && payload->load[1]=='O' && payload->load[2]=='S' && payload->load[3]=='T')        
        return POST_REQUEST;

    return -2;
}

static inline int is_port(int sport , int dport, int * alw_prt_list ){

    if(!alw_prt_list)
        return 0;

    for(int i=0;i<PORT_LIST_SIZE;i++){
        if(alw_prt_list[i] == dport || alw_prt_list[i] == sport)
            return 1;
    }
    return 0;
}


/*## Driver Code ##*/

SEC("classifier")

int perf_packet(struct __sk_buff *skb)
{
    int rc = TC_ACT_OK;

    //PORT_LIST_SIZE=10
    int alw_prt_list[] = {5000,80,0,0,0,0,0,0,0,0};

    void *data_end = (void*)(__u64)skb->data_end;
    void *data = (void *)(__u64)skb->data;
    struct ethhdr *eth = data;

    //if IP    
    struct iphdr * ip = is_ip(eth,data_end);
    if(!ip){
        if(DEBUG_LEVEL_2) bpf_printk("HIT IP FILTER");
        goto EXIT;
    }
    int eth_hdr_len = sizeof(struct ethhdr);
        

    int ip_hdr_len      =   (ip->ihl<<2);
    __u16 total_pkt_len =   ntohs(ip->tot_len);

    //if TCP/UDP

    int src_port        =   0;    
    int dest_port       =   0;     
    int tl_hdr_len      =   0;        

    if(ip->protocol == IPPROTO_TCP){

        struct tcphdr * tcp = is_tcp(ip,data_end);
        if(!tcp){
            if(DEBUG_LEVEL_2) bpf_printk("HIT TCP FILTER");        
            goto EXIT;
        }
        src_port    =   ntohs(tcp->source);
        dest_port   =   ntohs(tcp->dest);  
        tl_hdr_len  =   (tcp->doff<<2);    
    }

    else if(ip->protocol == IPPROTO_UDP){

        struct  udphdr * udp = is_udp(ip,data_end);
        if(!udp){
            if(DEBUG_LEVEL_2) bpf_printk("HIT UDP FILTER");        
            goto EXIT;
        }

        src_port    =   ntohs(udp->source);
        dest_port   =   ntohs(udp->dest);  
        tl_hdr_len  =   sizeof(*udp);    
    }

    // if PORT IS IN MONITOR LIST
    int port_flag = is_port(src_port,dest_port,alw_prt_list);

    if(!port_flag){
        if(DEBUG_LEVEL_2) bpf_printk("HIT PORT FILTER");        
        goto EXIT;
    }

    int payload_offset = eth_hdr_len+ ip_hdr_len + tl_hdr_len;

    int status = bpf_skb_pull_data(skb,total_pkt_len);
    
    if(status==-1) {
        if(DEBUG_LEVEL_1) 
            bpf_printk("DATA pull failed");
        goto EXIT;
    }
    data = (void*)(__u64)skb->data; 
    data_end = (void*)(__u64)skb->data_end;

    struct event *e;
    int zero = 0;
    
    e = bpf_map_lookup_elem(&user_event_data, &zero);
    if (!e) /* can't happen */
        return 0;

    if( ( (void*)data + payload_offset+ sizeof(e->payload) ) > data_end )
        goto EXIT;

    status = bpf_probe_read_kernel_str(&e->payload, sizeof(e->payload) , (void*)data+payload_offset);

    if(status<0) {
        if(DEBUG_LEVEL_1) 
            bpf_printk("kernel copy failed");
        goto EXIT;
    }

    bpf_perf_event_output(skb, &pb, BPF_F_CURRENT_CPU, e, sizeof(*e));

ERROR:

EXIT:
    if(DEBUG_LEVEL_1) bpf_printk("-------------  Code Over  ---------------\n");
	return rc;
}

char LICENSE[] SEC("license") = "GPL";

/*-------------------------------------------*/
// char fmt [] = "count : %d\n";
// int fmt_size = sizeof(fmt);