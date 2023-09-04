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

/*## Globals ##*/
pid_t my_pid = 0;

/*## MAPS ##*/

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_ENTRIES);
    __type(value, ud_t);
    __type(key, u32);
} user_map SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_ARRAY);
//     __uint(max_entries, MAX_URI_MAP_ENTRIES);
//     __type(value, uri_map_t);
//     __type(key, u32);
// } uri_map SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 16*1024);
// } rb SEC(".maps");

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
    char c[1400];
};

struct http_response{
    char http[8];
    char b1;
    char scode[3];
    char b2;
};

struct uri_s{
    char p1[3];
    char b1;
    char p2[3];
};

// Never count the extra spaces -- 
struct uri_l{
    char p1[3];
    char b1;
    char p2[8];
};

struct get_request_s{
    char req[3];
    char b1[2];
    struct uri_s uri;
    char b2;
    char http[8];
    char end;
};

struct get_request_l{
    char req[3];
    char b1[2];
    struct uri_l uri;
    char b2;
    char http[8];
    char end;
};

///nausf-auth/v1/ue-authentications

struct uri_t{
    char b1;
    char u1[10];
    char b2;
    char u2[2];
    char b3;
    char u3[18];
};

struct post_request {
    char req[4];
    char b1;
    struct uri_t uri;
    char b2;
    char http[8];
    char endl;
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

    if(payload->load[0]=='P' && payload->load[1]=='U' && payload->load[2]=='T' )        
        return PUT_REQUEST;
    return -2;
}

static inline int is_port(int sport , int dport){

    if(PORT == dport || PORT == sport)
        return 1;
    return 0;
}


/*## Driver Code ##*/
// char * uri = "ue-authentications";
int uri [18] = {117, 101, 45, 97, 117 ,116, 104, 101, 110, 116, 105, 99 ,97 ,116, 105, 111, 110, 115};

SEC("classifier")

int handle_egress(struct __sk_buff *skb)
{
    int rc = TC_ACT_OK;

    //PORT_LIST_SIZE=10
    // int alw_prt_list[] = {80,5000,0,0,0,0,0,0,0,0};

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
    if(ip->protocol !=IPPROTO_TCP && ip->protocol!=IPPROTO_UDP)
        goto EXIT;

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
    // if UDP
    else{

        struct  udphdr * udp = is_udp(ip,data_end);
        if(!udp){
            if(DEBUG_LEVEL_2) bpf_printk("HIT UDP FILTER");        
            goto EXIT;
        }

        src_port    =   ntohs(udp->source);
        dest_port   =   ntohs(udp->dest);  
        tl_hdr_len  =   sizeof(*udp);    
    }

    // if PORT Filter
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
            bpf_printk("ERROR  : DATA pull failed");
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

    // if request type==POST filter

    if(http_flag==POST_REQUEST){
        
        // POST /nausf-auth/v1/ue-authentications
        //
        if(DEBUG_LEVEL_1) bpf_printk("GOT POST REQUEST AT PORT\t%d",dest_port);        
    
        struct post_request * pr = NULL;

        if(((void *) data + payload_offset + sizeof(*pr)) > data_end)
            goto EXIT;

        pr = (struct post_request *) ((void *)data + payload_offset);

        int flag=-1;

        if(pr->b1 != ' ' || pr->b2 != ' '){
            if(DEBUG_LEVEL_1) bpf_printk("ERROR : 1");
            goto URI_NOT_MATCH;
        }

        if(pr->uri.b1!='/' || pr->uri.b2!='/' || pr->uri.b3!='/'){
            if(DEBUG_LEVEL_1) bpf_printk("ERROR : 2");
            goto URI_NOT_MATCH;
        }

        if(pr->uri.u1[0]!='n' || pr->uri.u1[1]!='a' || pr->uri.u1[2]!='u' || pr->uri.u1[3]!='s' || pr->uri.u1[4]!='f' || pr->uri.u1[5]!='-' || pr->uri.u1[6]!='a' || pr->uri.u1[7]!='u' || pr->uri.u1[8]!='t' || pr->uri.u1[9]!='h'){
           if(DEBUG_LEVEL_1) bpf_printk("ERROR : 3");
            goto URI_NOT_MATCH;
        }

        if(pr->uri.u2[0]!='v' || pr->uri.u2[1]!='1'){
           if(DEBUG_LEVEL_1) bpf_printk("ERROR : 4");

            goto URI_NOT_MATCH;
        }

        for(int i=0;i<18;i++){
            if((int)(pr->uri.u3[i])!=uri[i]){
              if(DEBUG_LEVEL_1)  bpf_printk("ERROR : 5");
                goto URI_NOT_MATCH;
            }
        }

        u32 key = COUNTER_KEY;
        ud_t * ud = (ud_t *)bpf_map_lookup_elem(&user_map,&key);

        if(ud==NULL)
            goto EXIT;

        ud->counter+=1;
        bpf_map_update_elem(&user_map,&key,ud,BPF_ANY);
    }

ERROR:

URI_NOT_MATCH:

     // if(DEBUG_LEVEL_1) bpf_printk("ERROR : uri Not Match");

EXIT:
    if(DEBUG_LEVEL_1) bpf_printk("-------------  Code Over  ---------------\n");
	return rc;
}

char LICENSE[] SEC("license") = "GPL";

/*-------------------------------------------*/
// char fmt [] = "count : %d\n";
// int fmt_size = sizeof(fmt);