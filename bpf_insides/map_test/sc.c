#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netdb.h>
#include <net/if.h>
#include <linux/pkt_cls.h>
#include <linux/if_arp.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include "sc.h"
#include "sc.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

int roundup(int n ,int r){
    return r*(n/r + (n%r==0?0:1));
}

int main(int argc, char **argv)
{
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = if_nametoindex(INTERFACE_NAME), .attach_point = BPF_TC_INGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .handle = 1, .priority = 1);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct sc *skel = sc__open_and_load();
    if(skel == NULL)
    {
        printf("Error : Program Load Failed\n");
        return 0;
    }
    printf("INFO : Program Loaded\n");

    // if(skel->bss == NULL){
    //     printf("INFO : No Global Var Support\n");
    // }    
    // else
    //     skel->bss->my_pid = getpid();

    bpf_tc_hook_create(&hook);
    hook.attach_point = BPF_TC_CUSTOM;

    hook.parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS);

    opts.prog_fd = bpf_program__fd(skel->progs.handle_egress);
    opts.prog_id = 0; 
    opts.flags = BPF_TC_F_REPLACE;

    
    bpf_tc_attach(&hook, &opts);
    printf("INFO : Program Attached\n");
    #ifdef MULTI_CORE
        int num_cpus = libbpf_num_possible_cpus();   
    #else 
        int num_cpus = 1;   
    #endif
    printf("INFO : CPU's used :: %d\n",num_cpus);

    // get map fd
    int map_fd = bpf_map__fd(skel->maps.storage_map);


    __u32 value_size = bpf_map__value_size(skel->maps.storage_map);
    printf("INFO : Value Size : %d\n",value_size);
    void * ud_data = (void *)malloc(roundup(value_size,8)*num_cpus);

    map_key_t map_key;

    map_key.key[0]='1';
    map_key.key[1]='0';

    
    int status;
    printf("STATUS :\n");
    while(exiting!=true){    
        uint32_t key = atoll((char *)map_key.key);

        status = bpf_map_lookup_elem(map_fd,&key,ud_data);
        map_value_t * map_value  = (map_value_t *) ud_data;

        if(status!=-1){
            printf("key : %d , value : %s",key,(char *)map_value->value);
            printf("\r");    
            fflush(stdout);
        }
        sleep(1);
    }
    printf("\n");
    close(map_fd);

    opts.flags = opts.prog_id = opts.prog_fd = 0;
    bpf_tc_detach(&hook, &opts);
    bpf_tc_hook_destroy(&hook);
    printf("INFO : Program Detached\n");
    return 0;
}
