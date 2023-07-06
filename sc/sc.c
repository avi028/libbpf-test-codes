#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netdb.h>
#include <linux/pkt_cls.h>
#include <linux/if_arp.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <unistd.h>

#include "sc.h"
#include "sc.skel.h"

static volatile bool exiting = false;


// void lps(int * pt , int n, char * p){
    
//     int l=0,i=1;
//     pt[l]=0;
//     while(i<n){
//         if(p[i]==p[l]){
//             pt[i]=l+1;
//             l+=1;
//             i+=1;
//         }
//         else{
//             if(l!=0){
//                 l=pt[l-1];              
//             }
//             else{
//                 pt[i]=0;
//                 i+=1;
//             }
//         }
//     }
// }


static void sig_handler(int sig)
{
    exiting = true;
}

static int handle_evt(void *ctx, void *data, size_t sz)
{
    const struct bpf_info *bi = data;

    fprintf(stdout, "count: %d \n", bi->count);

    return 0;
}


// ifindex 1 -> loopback
// ifindex 2 -> ethernet
// ifindex 3 -> wifi

int main(int argc, char **argv)
{
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = 1, .attach_point = BPF_TC_EGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .handle = 1, .priority = 1);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct sc *skel = sc__open_and_load();
    if(skel == NULL)
    {
        printf("Error : Program Load Failed\n");
        return 0;
    }
    printf("Program Loaded\n");

    skel->bss->my_pid = getpid();

    bpf_tc_hook_create(&hook);
    hook.attach_point = BPF_TC_CUSTOM;

    hook.parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);

    opts.prog_fd = bpf_program__fd(skel->progs.handle_egress);
    opts.prog_id = 0; 
    opts.flags = BPF_TC_F_REPLACE;

    bpf_tc_attach(&hook, &opts);
    printf("Program Attached\n");
    
    // int map_fd = bpf_map__fd(skel->maps.data);

    // int key=1;
    // ud_t ud ;
    // strcpy(ud.s,"aabcaaabcbc");
    // strcpy(ud.p,"aabc");
    // ud.s_len = 11;
    // ud.p_len = 4;

    // lps(ud.pt , ud.p_len , ud.p);

    // // for(int i=0;i<ud.p_len;i++)
    // //     printf("%d ",ud.pt[i]);

    // bpf_map_update_elem(map_fd, &key, &ud, 0);
    
    // struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_evt, NULL, NULL);
    while(exiting!=true){
        // ring_buffer__poll(rb, 1000);
    }

    opts.flags = opts.prog_id = opts.prog_fd = 0;
    int dtch = bpf_tc_detach(&hook, &opts);
    int dstr = bpf_tc_hook_destroy(&hook);

    printf("%d -- %d\n", dtch, dstr);
    
    return 0;
}
