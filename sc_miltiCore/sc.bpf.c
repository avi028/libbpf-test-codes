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
#define DEBUG_LEVEL_2 1
#define DEBUG_LEVEL_1 1
#define MIN_HTTP_HEADER 50
#define PORT_LIST_SIZE 10
#define NOT_HTTP 0
#define HTTP_RESPONSE 1
#define GET_REQUEST 2
#define POST_REQUEST 3

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
    char c[500];
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

struct post_request {
    char req[4];
    char b1;
    char uri[16];
    char b2;
    char http[8];
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
    bpf_printk("%d %d\n", sport,dport);

    for(int i=0;i<PORT_LIST_SIZE;i++){
        if(alw_prt_list[i] == dport || alw_prt_list[i] == sport)
            return 1;
    }
    return 0;
}


/*## Driver Code ##*/

SEC("classifier")

int handle_egress(struct __sk_buff *skb)
{
    int rc = TC_ACT_OK;

    //PORT_LIST_SIZE=10
    int alw_prt_list[] = {80,0,0,0,0,0,0,0,0,0};

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


    if(( eth_hdr_len+ ip_hdr_len + tl_hdr_len + MIN_HTTP_HEADER) > total_pkt_len ){
        if(DEBUG_LEVEL_1) bpf_printk("HIT HTTP LENGTH FILTER");        
        goto EXIT;
    }
    
    int payload_offset = eth_hdr_len+ ip_hdr_len + tl_hdr_len;
    
    // bpf_printk("struct Len : %d\t Tot len : %d",payload_offset,total_pkt_len);

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

    ud_t * ud = NULL;
    u32 key = COUNTER_KEY;

    if(http_flag==HTTP_RESPONSE){
    
        // http response code read with constant size
        if(DEBUG_LEVEL_1) bpf_printk("GOT HTTP RESPONSE AT PORT\t%d",dest_port);        
    
        struct http_response * hr = NULL;

        if(((void *) data + payload_offset + sizeof(*hr)) > data_end)
            goto EXIT;

        hr = (struct http_response *) ((void *)data + payload_offset);

        for(int i=0;i<sizeof(hr->scode);i++)
            if(DEBUG_LEVEL_1) bpf_printk("Http : %d",(hr->scode[i]-48));    

        ud = (ud_t *)bpf_map_lookup_elem(&user_map,&key);

        if(!(hr->scode[0]=='2' && hr->scode[1]=='0' && hr->scode[2]=='0'))
            goto EXIT;

        struct char500 * c_ptr = NULL;    
        
        if(((void*)data + payload_offset + sizeof(*c_ptr)) > data_end )
            goto EXIT;
              
        c_ptr = (struct char500 *) ((void*)data+payload_offset);
        int i=0;
        int flag=0;

        // for(i=0;flag == 0 && i<(sizeof(*c_ptr)-4);i++){
        //     if(flag==0 && c_ptr->c[i]=='\r' && c_ptr->c[i+1]=='\n' && c_ptr->c[i+2]=='\r' && c_ptr->c[i+3]=='\n'){
        //         i = i+4;
        //         flag=1;
        //     }
        // }

        // for( ;flag ==1 && i<sizeof(*c_ptr);i++){
        //     if(c_ptr->c[i]=='1' && i == sizeof(*c_ptr)-1){
        //         flag=-1;
        //     }
        // }

        for(i=0; i<(sizeof(*c_ptr)-4);i++){

            if(flag==0 && c_ptr->c[i]=='\r' && c_ptr->c[i+1]=='\n' && c_ptr->c[i+2]=='\r' && c_ptr->c[i+3]=='\n'){
                i +=4;
                flag=1;
                // http_header_len = i;
            }
            if(flag==1 && c_ptr->c[i]=='1'){
                flag=-1;
            }
        }


        // for(; flag ==1 && i<sizeof(c_ptr->c);i++){
        //     if( c_ptr->c[i]=='1' && i == (sizeof(*c_ptr)-1) ) {
        //         flag=-1;
        //     }
        // }

        if(flag== -1){
            // if(c_ptr)
            //     c_ptr->c[0]='G';
            if(ud){        
                ud->counter+=1;
                bpf_map_update_elem(&user_map,&key,ud,BPF_ANY);
            }
        }


        // if(DEBUG_LEVEL_1) bpf_printk("http header len %d",i);

        // int http_hdr_len  = i+4+1;

        // payload_offset +=http_hdr_len;

        // struct char100 * cptr = NULL;

        // if(((void*)data + payload_offset + sizeof(*cptr)) > data_end )
        //     goto EXIT;


        // cptr = (struct char100 *) ((void*)data+payload_offset);

        // if(DEBUG_LEVEL_1) bpf_printk("char at %d : %d",i,cptr->c[0]);
        // if(DEBUG_LEVEL_1) bpf_printk("char at %d : %d",i,cptr->c[1]);
        // if(DEBUG_LEVEL_1) bpf_printk("char at %d : %d",i,cptr->c[2]);
        // if(DEBUG_LEVEL_1) bpf_printk("char at %d : %d",i,cptr->c[3]);           
    }

    else if(http_flag == GET_REQUEST){        

        // get request uri sub parts of size-range read at constant time
        if(DEBUG_LEVEL_1) bpf_printk("SENT GET REQUEST FROM PORT\t%d",src_port);                

        struct get_request_s * grs = NULL;
        struct get_request_l * grl = NULL;
        
        // set the smallest uri-length test first
        if(((void *) data + payload_offset + sizeof(*grs)) > data_end)
            goto EXIT;

        grs = (struct get_request_s *) ((void*)data + payload_offset);
        if(grs->end == '\r'){
            for(int i=0;i<sizeof(grs->uri.p2);i++)
                if(DEBUG_LEVEL_1)  bpf_printk("uri[%d] : %d",i,(grs->uri.p2[i]));    
            goto EXIT;
        }
    
        // set the second smallest uri-length test
        if(((void *) data + payload_offset + sizeof(*grl)) > data_end)
            goto EXIT;

        grl = (struct get_request_l *) ((void*)data + payload_offset);
        if(grl->end == '\r'){
            for(int i=0;i<sizeof(grl->uri.p2);i++)
                if(DEBUG_LEVEL_1) bpf_printk("uri[%d] : %d",i,(grl->uri.p2[i]));    
            goto EXIT;
        }

        // set the third smallest uri-length test 

        // code ....

    }

    else if(http_flag == POST_REQUEST){

        // get request uri of constant size read at constant time
        if(DEBUG_LEVEL_1) bpf_printk("SENT POST REQUEST FROM PORT\t%d",src_port);

        struct post_request * gr = NULL;

        if(((void *) data + payload_offset + sizeof(*gr)) > data_end)
            goto EXIT;

        gr = (struct post_request *) ((void*)data + payload_offset);
        for(int i=0;i<sizeof(gr->uri);i++)
            if(DEBUG_LEVEL_1)  bpf_printk("uri[%d] : %d",i,(gr->uri[i]));
    }

ERROR:

EXIT:
    if(DEBUG_LEVEL_1) bpf_printk("-------------  Code Over  ---------------\n");
	return rc;
}

char LICENSE[] SEC("license") = "GPL";

/*-------------------------------------------*/
// char fmt [] = "count : %d\n";
// int fmt_size = sizeof(fmt);