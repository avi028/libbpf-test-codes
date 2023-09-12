#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "sc.h"

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
#define MIN_HTTP_HEADER 50
#define PORT_LIST_SIZE 10
#define NOT_HTTP 0
#define HTTP_RESPONSE 1
#define GET_REQUEST 2
#define POST_REQUEST 3
#define PUT_REQUEST 4
#define DELETE_REQUEST 5

/*## Globals ##*/
pid_t my_pid = 0;

/*## MAPS ##*/

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(value, ud_t);
    __type(key, mapkey_t);
} user_map SEC(".maps");

/*## STRUCTS ##*/

struct p_data{
    char load[MIN_HTTP_HEADER];
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

   if(payload->load[0]=='P' && payload->load[1]=='U' && payload->load[2]=='T')        
        return PUT_REQUEST;

    if(payload->load[0]=='D' && payload->load[1]=='E' && payload->load[2]=='L' && payload->load[3]=='E' && payload->load[4]=='T' && payload->load[5]=='E')        
        return DELETE_REQUEST;
    return -2;
}

static inline int is_port(int sport , int dport){

    if(PORT == dport || PORT == sport)
        return 1;
    return 0;
}


/*## Driver Code ##*/

SEC("classifier")

int handle_egress(struct __sk_buff *skb)
{
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
    int port_flag = is_port(src_port,dest_port);
    if(!port_flag){
        if(DEBUG_LEVEL_2) bpf_printk("HIT PORT FILTER");        
        goto EXIT;
    }

    if(( eth_hdr_len+ ip_hdr_len + tl_hdr_len + MIN_HTTP_HEADER) > total_pkt_len ){
        if(DEBUG_LEVEL_1) bpf_printk("HIT HTTP LENGTH FILTER");        
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

    // if HTTP Request/Response

    int http_flag = is_http(skb,payload_offset);

    if(http_flag <= 0 ){
        if(DEBUG_LEVEL_1) bpf_printk("HIT HTTP FILTER : %d",http_flag);        
        goto EXIT;
    }


    if(http_flag==POST_REQUEST){
        if(DEBUG_LEVEL_1) bpf_printk("POST REQUEST AT PORT\t%d",dest_port);
        payload_offset+=5;
    }

    if(http_flag==PUT_REQUEST){
        if(DEBUG_LEVEL_1) bpf_printk("PUT REQUEST AT PORT\t%d",dest_port);
        payload_offset+=4;
    }

    if(http_flag==DELETE_REQUEST){
        if(DEBUG_LEVEL_1) bpf_printk("DELETE REQUEST AT PORT\t%d",dest_port);
        payload_offset+=7;
    }

    if(http_flag==GET_REQUEST){
        if(DEBUG_LEVEL_1) bpf_printk("GET REQUEST AT PORT\t%d",dest_port);
        payload_offset+=4;
    }

    if(http_flag==HTTP_RESPONSE){
        if(DEBUG_LEVEL_1) bpf_printk("HTTP RESPONSE AT PORT\t%d",dest_port);
        payload_offset+=5;
    }
    
    mapkey_t * key =    NULL ;  
    if(((void *) data + payload_offset+ sizeof(* key)) > data_end)
        goto EXIT;

    key = (mapkey_t *) ((void *)data + payload_offset);

    ud_t * ud = (ud_t *)bpf_map_lookup_elem(&user_map,(const void *)key);

    if(ud==NULL)
        goto EXIT;

    ud->counter+=1;
//    bpf_map_update_elem(&user_map,&key,ud,BPF_ANY);

EXIT:
    if(DEBUG_LEVEL_1) bpf_printk("-------------  Code Over  ---------------\n");
	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";

/*-------------------------------------------*/
// char fmt [] = "count : %d\n";
// int fmt_size = sizeof(fmt);