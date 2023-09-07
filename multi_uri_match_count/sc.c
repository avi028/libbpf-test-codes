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

static int handle_evt(void *ctx, void *data, size_t sz)
{
    const struct bpf_info *bi = data;

    fprintf(stdout, "count: %d \n", bi->count);

    return 0;
}

int initialize_bpf_array(int fd)
{
        int ncpus = libbpf_num_possible_cpus();
        ud_t  ud[ncpus];
        __u32 i, j;
        int ret;

        for (i = 0; i < MAX_ENTRIES ; i++) {
                for (j = 0; j < ncpus; j++)
                        ud[j].counter = 0;
                ret = bpf_map_update_elem(fd, &i, &ud, BPF_ANY);
                if (ret < 0)
                        return ret;
        }

        return ret;
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

    if(skel->bss == NULL){
        printf("INFO : No Global Var Support\n");
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
    printf("INFO : Program Attached\n");
    int num_cpus = libbpf_num_possible_cpus();    
    printf("INFO : CPU's - %d\n",num_cpus);

    // get map fd
    int map_fd = bpf_map__fd(skel->maps.user_map);

    // initialize the map with zeros
    unsigned int key_set [6] = {3,13,23,25,34,35};
    unsigned int  key;

    __u32 value_size = bpf_map__value_size(skel->maps.user_map);
    void * ud_data = (void *)malloc(roundup(value_size,8)*num_cpus);

    int per_cpu_sum[6];
    int status;
    printf("STATUS :\n");
    while(exiting!=true){    
        for(int itr=0;itr<6;itr++){
            key = key_set[itr];
            status = bpf_map_lookup_elem(map_fd,&key,ud_data);
            if(status!=-1){
            per_cpu_sum[itr]=0;
            for(int i=0;i<num_cpus;i++){
                    per_cpu_sum[itr]+=(int)*((long *)ud_data + i);
                }
            }
            printf("URI%d\t%d\t",itr+1,per_cpu_sum[itr]);
        }
        printf("\r");    
        fflush(stdout);
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
