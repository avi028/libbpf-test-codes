#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "sc.h"

//#include <linux/pkt_cls.h>
#define TC_ACT_UNSPEC   (-1)
#define TC_ACT_OK       0
#define TC_ACT_RECLASSIFY   1
#define TC_ACT_SHOT     2
#define TC_ACT_PIPE     3
#define TC_ACT_STOLEN       4
#define TC_ACT_QUEUED       5
#define TC_ACT_REPEAT       6
#define TC_ACT_REDIRECT     7
#define TC_ACT_TRAP     8

// #def not available in vmlinux.h
#define ETH_P_IP    0x0800

// for easy understanding 
#define htons bpf_htons
#define ntohl bpf_ntohl
#define ntohs bpf_ntohs

// user defined #def
#define MIN_HTTP_HEADER 50

#define NOT_HTTP 0
#define HTTP_RESPONSE 1
#define GET_REQUEST 2
#define POST_REQUEST 3
#define PUT_REQUEST 4
#define DELETE_REQUEST 5

#define REQ_SIZE 6

#define U1_SIZE 10
#define U2_SIZE 2
#define U3_SIZE 18
#define UR1_SIZE 10
#define UR2_SIZE 11
#define UR3_SIZE 19

#define UR1_OFFSET 0
#define UR2_OFFSET 37 
#define UR3_OFFSET 37

/*## Globals ##*/
pid_t my_pid = 0;
            
int req[REQ_SIZE] = {-1,5,4,5,4,7} ; // req[#PUT_REQUEST] = sizeof("PUT")+1
int u1 [U1_SIZE] = {110, 97, 117, 115, 102, 45, 97, 117, 116, 104}; //nausf-auth
int u2 [U2_SIZE] = {118, 49}; //v1
int u3 [U3_SIZE] = {117, 101, 45, 97, 117 ,116, 104, 101, 110, 116, 105, 99 ,97 ,116, 105, 111, 110, 115}; //ue-authentications
int ur1[UR1_SIZE] = {100, 101, 114, 101, 103, 105, 115, 116, 101, 114}; //   deregister
int ur2[UR2_SIZE] = {101, 97, 112, 45, 115, 101, 115, 115, 105, 111, 110}; //eap-session
int ur3[UR3_SIZE] = {53, 103, 45, 97, 107, 97, 45, 99, 111, 110, 102, 105, 114, 109, 97, 116, 105, 111, 110}; // 5g-aka-confirmation 

/*## MAPS ##*/
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_ENTRIES);
    __type(value, ud_t);
    __type(key, u32);
} user_map SEC(".maps");

/*## STRUCTS ##*/

struct p_data{
    char load[MIN_HTTP_HEADER];
};

struct http_response{
    char http[8];
    char b1;
    char scode[3];
    char b2;
};

struct uri_t{
    char b0;
    char u1[U1_SIZE];
    char b1;
    char u2[U2_SIZE];
    char b2;
    char u3[U3_SIZE];
    char b3;
};

struct ur1_t {
    char ur[UR1_SIZE];
}; 

struct ur2_t {
    char ur[UR2_SIZE];
}; 

struct ur3_t {
    char ur[UR3_SIZE];
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

    if(payload->load[0]=='P' && payload->load[1]=='U' && payload->load[2]=='T' )        
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

    // if(DEBUG_LEVEL_1){
    //     if(http_flag==POST_REQUEST)
    //         
    //     if(http_flag==GET_REQUEST)
    //         bpf_printk("GET REQUEST AT PORT\t%d",dest_port);
    //     if(http_flag==PUT_REQUEST)
    //         bpf_printk("PUT REQUEST AT PORT\t%d",dest_port);
    //     if(http_flag==DELETE_REQUEST)
    //         bpf_printk("DELETE REQUEST AT PORT\t%d",dest_port);
    //     if(http_flag==HTTP_RESPONSE)
    //         bpf_printk("HTTP RESPONSE AT PORT\t%d",dest_port);
    // }

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

    struct uri_t * uri =    NULL ;  
    if(((void *) data + payload_offset+ sizeof(* uri)) > data_end)
        goto EXIT;

    uri = (struct uri_t *) ((void *)data + payload_offset);

    int uri_flag=-1;

    if(uri->b0!='/' || uri->b1!='/' || uri->b2!='/'){
        if(DEBUG_LEVEL_1) bpf_printk("ERROR : Mismatch at / ");
        goto EXIT;
    }

    for(int i=0;i<U1_SIZE;i++){
        if((int)(uri->u1[i])!=u1[i]){
          if(DEBUG_LEVEL_1)  bpf_printk("ERROR : Mismatch at U1");
            goto EXIT;
        }
    }

    for(int i=0;i<U2_SIZE;i++){
        if((int)(uri->u2[i])!=u2[i]){
          if(DEBUG_LEVEL_1)  bpf_printk("ERROR : Mismatch at U2");
            goto EXIT;
        }
    }

    for(int i=0;i<U3_SIZE;i++){
        if((int)(uri->u3[i])!=u3[i]){
          if(DEBUG_LEVEL_1)  bpf_printk("ERROR : Mismatch at U3");
            goto EXIT;
        }
    }

    // uri-flag 0 check
    if(uri->b3==' '){
        uri_flag=0;
        goto MAP_UPDATE;
    }

    if(uri->b3!='/'){
        uri_flag=-1;
          if(DEBUG_LEVEL_1)  bpf_printk("ERROR : Mismatch at UR");
        goto EXIT;
    }

    payload_offset += sizeof(struct uri_t);

    // uri_flag 1 check
    if(((void *) data + payload_offset +UR1_OFFSET+ sizeof(struct ur1_t)) > data_end)
        goto EXIT;

    struct ur1_t * ur1_p = (struct ur1_t *) ((void *)data + payload_offset + UR1_OFFSET);
    uri_flag = 1;

    for(int i=0;i<UR1_SIZE;i++){
        if((int)(ur1_p->ur[i])!=ur1[i]){
          if(DEBUG_LEVEL_1)  bpf_printk("ERROR : Mismatch at UR1");
          uri_flag=-1;
          break;
        }
    }
    if(uri_flag==1)
        goto MAP_UPDATE;

    // uri_flag 2 check
    if(((void *) data + payload_offset +UR2_OFFSET+ sizeof(struct ur2_t)) > data_end)
        goto EXIT;

    struct ur2_t * ur2_p = (struct ur2_t *) ((void *)data + payload_offset + UR2_OFFSET);
    uri_flag = 2;

    for(int i=0;i<UR2_SIZE;i++){
        if((int)(ur2_p->ur[i])!=ur2[i]){
          if(DEBUG_LEVEL_1)  bpf_printk("ERROR : Mismatch at UR2");
          uri_flag=-1;
          break;
        }
    }
    if(uri_flag==2)
        goto MAP_UPDATE;

    // uri_flag 3 check
    if(((void *) data + payload_offset +UR3_OFFSET+ sizeof(struct ur3_t)) > data_end)
        goto EXIT;

    struct ur3_t * ur3_p = (struct ur3_t *) ((void *)data + payload_offset + UR3_OFFSET);
    uri_flag = 3;

    for(int i=0;i<UR3_SIZE;i++){
        if((int)(ur3_p->ur[i])!=ur3[i]){
          if(DEBUG_LEVEL_1)  bpf_printk("ERROR : Mismatch at UR3");
          uri_flag=-1;
          break;
        }
    }
    if(uri_flag==3)
        goto MAP_UPDATE;


MAP_UPDATE:
    if(uri_flag==-1)
        goto EXIT;

    u32 key = uri_flag*10+http_flag;
    ud_t * ud = (ud_t *)bpf_map_lookup_elem(&user_map,&key);

    if(ud==NULL){
        if(DEBUG_LEVEL_1) bpf_printk("ERROR: Map Upadet failed for key %d",key);
        goto EXIT;
    }

    ud->counter+=1;
    if(DEBUG_LEVEL_2) bpf_printk("INFO: Map Upadte for key %d",key);
    bpf_map_update_elem(&user_map,&key,ud,BPF_ANY);
    
EXIT:
    if(DEBUG_LEVEL_1) bpf_printk("-------------  Code Over  ---------------\n");
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";

/*-------------------------------------------*/
// char fmt [] = "count : %d\n";
// int fmt_size = sizeof(fmt);