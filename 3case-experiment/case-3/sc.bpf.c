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
#define ETH_HEADER_SIZE 14

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

// Auto generated DEF's
#define SKIP_POST_HEADER 159
#define SKIP_PUT_HEADER 158
#define SKIP_HTTP_HEADER 159
#define SKIP_GET_HEADER 158
#define SKIP_DELETE_HEADER 161
#define TOTAL_ATTRIBUTES 26
#define ATTR1_LEN 40

// /*## Globals ##*/
// pid_t my_pid = 0;

/*## MAPS ##*/
struct {

    #ifdef MULTI_CORE
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    #else
    __uint(type, BPF_MAP_TYPE_ARRAY);
    #endif

    __uint(max_entries, MAX_ENTRIES);
    __type(value, ud_t);
    __type(key, u32);
} user_map SEC(".maps");

/*## STRUCTS ##*/

struct p_data{
    char load[MIN_HTTP_HEADER];
};

// #define M 25

struct c1 {
    char c[1];
};

struct c8 {
    __u64 attr;
};

// __u64 u64_l1[M] = { 1650532896,1785292903,1987145839,841103906,1685283176,862466608,1684234849,1818978921,1953722993,857881122,1634952755,2033477221,1629629474,1768449894,1903193966,862479906,1935962994,2257512};
// __u64 u64_l1[M] =  { 7450754115369591074,8029475498074204520,2484431702755537264,7508400220715229754,3487585331155596129,6999205297142327346,7595434461045744482,8174155843750357866,2483866545155240818,3689068447900312122,7306091357634917222,2465498924056130662,7378413942531498540,7957135325236127847,2466321625175388271,8229035783813818470,3544395997368247411,3546645412514640690,7526133123665769266,4134707374788407859,3978425819141910832,3617349713863520568,7958815413493786738,3833745473465760097,2464651186745653046};

//__u8 u64_l1[M] = {'"','a','b','"',':','"','o','4','i','5','f','4','3','2','1','0','"',','};
// __u8 s1[10] = {'"','a','b','"',':','"','o','4','i','"'};




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
    __u16 total_pkt_len =   ntohs(ip->tot_len) + ETH_HEADER_SIZE;

    //if TCP/UDP
    if(ip->protocol !=IPPROTO_TCP && ip->protocol!=IPPROTO_UDP)
        goto EXIT;

    int src_port        =   0;    
    int dest_port       =   0;     
    int tl_hdr_len      =   0;        

    //if TCP
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
    // int http_flag = is_http(skb,payload_offset);

    // if(http_flag <= 0 ){
    //     if(DEBUG_LEVEL_1) bpf_printk("HIT HTTP FILTER : %d",http_flag);
    //     goto EXIT;
    // }

    // if(http_flag==POST_REQUEST){
    //     if(DEBUG_LEVEL_1) bpf_printk("POST REQUEST AT PORT\t%d",dest_port);
    //     payload_offset+=SKIP_POST_HEADER;
    // }

    // if(http_flag==PUT_REQUEST){
    //     if(DEBUG_LEVEL_1) bpf_printk("PUT REQUEST AT PORT\t%d",dest_port);
    //     payload_offset+=SKIP_PUT_HEADER;
    // }

    // if(http_flag==DELETE_REQUEST){
    //     if(DEBUG_LEVEL_1) bpf_printk("DELETE REQUEST AT PORT\t%d",dest_port);
    //     payload_offset+=SKIP_DELETE_HEADER;
    // }

    // if(http_flag==GET_REQUEST){
    //     if(DEBUG_LEVEL_1) bpf_printk("GET REQUEST AT PORT\t%d",dest_port);
    //     payload_offset+=SKIP_GET_HEADER;
    // }

    // if(http_flag==HTTP_RESPONSE){
    //     if(DEBUG_LEVEL_1) bpf_printk("HTTP RESPONSE AT PORT\t%d",dest_port);
    //     payload_offset+=SKIP_HTTP_HEADER;
    // }

    int attr_flag=-1;


    // wrie code for attribute check

    struct c1 * c1_ptr=NULL;

    if(((void *) data + payload_offset+ (sizeof(struct c1))> data_end)){
        if(DEBUG_LEVEL_1) bpf_printk("ERROR IN LENGTH ");
        goto EXIT;
    }
    
    c1_ptr = (struct c1 *) ((void*)data + payload_offset);

    if(c1_ptr->c[0] != '{'){
        if(DEBUG_LEVEL_1) bpf_printk("ERROR IN {");
        goto EXIT;
    }

    int itr=0,itr_n=0;
    struct c8 * c8_ptr=NULL;
    int m=0;
    int i=payload_offset;

    // max read upto 1543 byte in packet and bytes upto 200

    
    for(int j = 0 ; j < ATTR_NUM; j++) {
        if(((void *) data + i + (sizeof(struct c8)) <= data_end)){
            c8_ptr = (struct c8 *) ((void*) data + i);
            
            if (c8_ptr->attr & needed_mask == u64_needed_attr)
            {
                goto MAP_UPDATE;
            }
            
            for(m = 0; m < ATTR_NUM; m++) {
                if(c8_ptr->attr & mask[m] == u64_attr_list[m]) {
                    i += skip_bytes[m];
                    break;
                }
            }
                
                    
                    
            // if(m==M){
            //     attr_flag=1;
            //     goto MAP_UPDATE;
            // }
        }
       itr=i;
    }
    if(DEBUG_LEVEL_1) 
        bpf_printk("INFO : No Match Found till %d",itr);    
    goto EXIT;

MAP_UPDATE:
    
    if(attr_flag<0)
        goto EXIT;

    u32 key = http_flag * attr_flag;

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