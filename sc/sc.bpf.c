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
#define debug 1
#define MIN_HTTP_HEADER 16

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

    if((void *)ip_hdr + sizeof(*ip_hdr) + sizeof(*tcp_hdr) > data_end)
        return NULL;

    if(ip_hdr->protocol == IPPROTO_TCP)
        tcp_hdr = (struct tcphdr*)((void *)ip_hdr + sizeof(*ip_hdr));

    return tcp_hdr;
}


void * is_http(struct tcphdr * tcp_hdr , void * data_end){

    char * payload = NULL;

    if(!tcp_hdr || !data_end)
        return NULL;


    if((void*) eth_hdr + sizeof(*eth_hdr) + sizeof(*ip_hdr) > data_end)
    
}

// int is_port();



// Driver Code
SEC("classifier")

int handle_egress(struct __sk_buff *skb)
{
    int rc = TC_ACT_OK;

    void *data_end = (void*)(__u64)skb->data_end;
    void *data = (void *)(__u64)skb->data;
    struct ethhdr *eth = data;

    struct iphdr * ip = is_ip(eth,data_end);

    if(!ip){
        if(debug) bpf_printk("HIT IP FILTER");
        goto EXIT;
    }
    
    //if IS IP    
    struct tcphdr * tcp = is_tcp(ip,data_end);

    if(!tcp){
        if(debug) bpf_printk("HIT TCP FILTER");        
        goto EXIT;
    }

    //if IS TCP

    bpf_printk("SRC IP:\t%d\n", ntohs(ip->saddr));
    bpf_printk("SRC PORT:\t%d\n", ntohs(tcp->source));
    bpf_printk("DEST IP:\t%d\n", ntohs(ip->daddr));
    bpf_printk("DEST PORT:\t%d\n", ntohs(tcp->dest));



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