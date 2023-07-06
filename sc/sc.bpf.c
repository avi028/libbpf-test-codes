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
#define debug 0
#define MIN_HTTP_HEADER 5
#define PORT_LIST_SIZE 10
#define NOT_HTTP 0
#define HTTP_RESPONSE 1
#define GET_REQUEST 2
#define POST_REQUEST 3

// Globals
pid_t my_pid = 0;

// MAPS

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 10);
//     __type(value, ud_t);
//     __type(key, u32);
// } data SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 16*1024);
// } rb SEC(".maps");



// FUNCTIONS

struct iphdr * is_ip(struct ethhdr *eth_hdr,void * data_end){
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


struct tcphdr * is_tcp(struct iphdr * ip_hdr  ,  void * data_end){
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

struct p_data{
    char data[4];
};

int is_http(void * data , void * data_end ,int payload_offset){

    struct p_data * payload = NULL;

    if(!data || !data_end)
        return 0;

    if(((void *)data + payload_offset + sizeof(*payload)) > data_end)
        return -1;

    payload = (struct p_data * )((void *)data + payload_offset);

    if(payload->data[0]=='H' && payload->data[1]=='T' && payload->data[2]=='T' && payload->data[3]=='P')
         return HTTP_RESPONSE;

    if(payload->data[0]=='G' && payload->data[1]=='E' && payload->data[2]=='T')        
        return GET_REQUEST;

    if(payload->data[0]=='P' && payload->data[1]=='O' && payload->data[2]=='S' && payload->data[3]=='T')        
        return POST_REQUEST;

    return -2;
}

int is_port(struct tcphdr * tcp_hdr, int * alw_prt_list ){

    if(!tcp_hdr || !alw_prt_list)
        return 0;

    int sport = ntohs(tcp_hdr->source);
    int dport = ntohs(tcp_hdr->dest);

    for(int i=0;i<PORT_LIST_SIZE;i++){
        if(alw_prt_list[i] == dport || alw_prt_list[i] == sport)
            return 1;
    }
    return 0;
}



// Driver Code
SEC("classifier")

int handle_egress(struct __sk_buff *skb)
{
    int rc = TC_ACT_OK;

    //PORT_LIST_SIZE=10
    int alw_prt_list[] = {80,0,0,0,0,0,0,0,0,0};

    void *data_end = (void*)(__u64)skb->data_end;
    void *data = (void *)(__u64)skb->data;
    struct ethhdr *eth = data;

    struct iphdr * ip = is_ip(eth,data_end);
    if(!ip){
        if(debug) bpf_printk("HIT IP FILTER");
        goto EXIT;
    }
    int eth_hdr_len = sizeof(struct ethhdr);
    
    //if IS IP    
    struct tcphdr * tcp = is_tcp(ip,data_end);
    if(!tcp){
        if(debug) bpf_printk("HIT TCP FILTER");        
        goto EXIT;
    }
    int ip_hdr_len = (ip->ihl<<2);
    int total_pkt_len = ip->tot_len;

    //if IS TCP

    int port_flag = is_port(tcp,alw_prt_list);
    if(!port_flag){
        if(debug) bpf_printk("HIT PORT FILTER");        
        goto EXIT;
    }
    int src_port = ntohs(tcp->source);
    int dest_port = ntohs(tcp->dest);    
    int tcp_hdr_len = (tcp->doff<<2);


    // if port is in alw_prt_list

    if(( eth_hdr_len+ ip_hdr_len + tcp_hdr_len + MIN_HTTP_HEADER) > total_pkt_len )
        goto EXIT;
    
    int payload_offset = eth_hdr_len+ ip_hdr_len + tcp_hdr_len;
    
    bpf_skb_pull_data(skb,payload_offset+MIN_HTTP_HEADER);
    
    data = (void*)(__u64)skb->data;
    data_end = (void*)(__u64)skb->data_end;

    int http_flag = is_http(data,data_end,payload_offset);

    if(http_flag <= 0 ){
        if(debug) bpf_printk("HIT HTTP FILTER : %d",http_flag);        
        goto EXIT;
    }

    // if is HTTP Request/Response
    if(http_flag==HTTP_RESPONSE)
        bpf_printk("GOT HTTP RESPONSE AT PORT\t%d",dest_port);        
    else if(http_flag == GET_REQUEST)        
        bpf_printk("SENT GET REQUEST FROM PORT\t%d",src_port);                

ERROR:

EXIT:
	return rc;
}


    // char fmt [] = "count : %d\n";
    // int fmt_size = sizeof(fmt);


/*
    char s,p;
    int flag=0;
    u32 key = 1;
    ud_t * ud = bpf_map_lookup_elem(&data,&key);

    if(!ud){
        goto ERROR;
    }
*/


    // bpf_printk("SRC IP:\t%d\n", ntohs(ip->saddr));
    // bpf_printk("SRC PORT:\t%d\n", ntohs(tcp->source));
    // bpf_printk("DEST IP:\t%d\n", ntohs(ip->daddr));
    // bpf_printk("DEST PORT:\t%d\n", ntohs(tcp->dest));    


/*Ring Buffer Handling 
    struct bpf_info * bi = bpf_ringbuf_reserve(&rb, sizeof(*bi), 0);

    if(!bi){
        goto ERROR;
    }    

    
    bi->count=flag;
    bpf_ringbuf_submit(bi, 0);
*/

/* KMP Algorithm : 
    for(int j=0,i=0,total = 0; total < 1000 && j<ud->p_len && i<ud->s_len; total ++){
        if(i<11 && ud->s && j<4 && ud->p && ud->p[j]==ud->s[i]){
            i++;
            j++;
        }
        else{
            if(j>0 && ud->pt && j<4)
                j=ud->pt[j-1];
            else
                i++;
        }       
        flag=j;
    }
*/
char LICENSE[] SEC("license") = "GPL";