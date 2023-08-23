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
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = 4, .attach_point = BPF_TC_INGRESS);
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

    if(skel->bss == NULL){
        printf("No Global Var Support\n");
    }    
    else
        skel->bss->my_pid = getpid();

    bpf_tc_hook_create(&hook);
    hook.attach_point = BPF_TC_CUSTOM;

    hook.parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS);

    opts.prog_fd = bpf_program__fd(skel->progs.handle_egress);
    opts.prog_id = 0; 
    opts.flags = BPF_TC_F_REPLACE;

    
    bpf_tc_attach(&hook, &opts);
    printf("Program Attached\n");
    
    int map_fd = bpf_map__fd(skel->maps.user_map);
    ud_t  ud;
    ud.counter = 0;
    unsigned int  key  = COUNTER_KEY;

    bpf_map_update_elem(map_fd,&key,&ud,BPF_ANY);

    while(exiting!=true){
        int status = bpf_map_lookup_elem(map_fd,&key,&ud);
        // printf("map status %d", status);
        if(status!=-1){
            printf("200 Status Count: %d\r",ud.counter);
            fflush(stdout);
        }
        sleep(1);
    }
    printf("\n");
    close(map_fd);

    opts.flags = opts.prog_id = opts.prog_fd = 0;
    int dtch = bpf_tc_detach(&hook, &opts);
    int dstr = bpf_tc_hook_destroy(&hook);

    printf("%d -- %d\n", dtch, dstr);
    
    return 0;
}
