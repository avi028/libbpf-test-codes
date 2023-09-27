#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>


struct c1{
    char c[10];
};


/*## Driver Code ##*/
__u8 s [4]= {'1','1','2','3'};

SEC("classifier")
int handle_egress(struct __sk_buff *skb)
{
    void *data_end = (void*)(__u64)skb->data_end;
    void *data = (void *)(__u64)skb->data;

    int flag = -1;
    struct c1 * cptr = NULL; 
    #pragma clang loop unroll(full)
    for(int i=0;i<340;i++){

        if(((void*)data + i + sizeof(*cptr)) <= data_end ){
            cptr = (struct c1 *)(data + i); 
            for(int m=0;m<4;m++)
            if(cptr->c[m]==s[m] )
                flag+=1;                
        }
    }
    return flag;
    
}

char LICENSE[] SEC("license") = "GPL";

/*-------------------------------------------*/
// char fmt [] = "count : %d\n";
// int fmt_size = sizeof(fmt);