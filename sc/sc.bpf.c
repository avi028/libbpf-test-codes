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

pid_t my_pid = 0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(value, ud_t);
    __type(key, u32);
} data SEC(".maps");

SEC("classifier")

int handle_egress(struct __sk_buff *skb)
{
    int rc = TC_ACT_OK;

    void *data_end = (void*)(long)skb->data_end;
    struct ethhdr *eth = (struct ethhdr*)(void*)(long)skb->data;
    u32 key = 1;
    ud_t * ud = bpf_map_lookup_elem(&data,&key);
    char fmt [] = "count : %d\n";
    int fmt_size = sizeof(fmt);
    int i=0,j=0;
    int total = 0;
    char s,p;
    if(ud){        
        for(total = 0; total < 1000 ; total ++){
            if(i==ud->s_len)
                break;
            if(j==ud->p_len){
                break;
            }
            if(i<11 && i<ud->s_len && ud->s){
                s = ud->s[i];
            }          
            if(j<4 && ud->p){
                p = ud->p[j];
            }   
            if(s==p){
                i++;
                j++;
            }
            else{
                if(j>0 && ud->pt && j<4)
                    j=ud->pt[j-1];
                else
                    i++;
            }       
        }
    }
	return rc;
}

char LICENSE[] SEC("license") = "GPL";
