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

    if(skel->bss == NULL){
        printf("No Global Var Support\n");
    }    
    else
        skel->bss->my_pid = getpid();

    bpf_tc_hook_create(&hook);
    hook.attach_point = BPF_TC_CUSTOM;

    hook.parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);

    opts.prog_fd = bpf_program__fd(skel->progs.handle_egress);
    opts.prog_id = 0; 
    opts.flags = BPF_TC_F_REPLACE;

    
    bpf_tc_attach(&hook, &opts);
    printf("Program Attached\n");
    int num_cpus = libbpf_num_possible_cpus();    
    printf("INFO : CPU's - %d\n",num_cpus);

    int map_fd = bpf_map__fd(skel->maps.user_map);

    // initialize_bpf_array(map_fd);

    __u32 value_size = bpf_map__value_size(skel->maps.user_map);
    printf("INFO : Value Size - %d\n",value_size);
    printf("INFO : ud_t size - %d\n",sizeof(ud_t));

    void * ud_data = (void *)malloc(8*num_cpus);

    unsigned int  key  = COUNTER_KEY;

    int sum = 0,i=0;
    
    // for(i=0;i<num_cpus;i++){
    //     ud[i].counter = 0;
    // }
    // bpf_map_update_elem(map_fd,&key,ud,BPF_ANY);

    // for(i=0;i<num_cpus;i++){
    //     sum += ud[i].counter ;
    // }

    // if(DEBUG_LEVEL_2) printf("Initial sum : %d\n",sum);

    while(exiting!=true){
        int status = bpf_map_lookup_elem(map_fd,&key,ud_data);
        // printf("map status %d", status);
        if(status!=-1){
            sum=0;
            for(i=0;i<num_cpus;i++){
                     sum+=(int)*((long *)ud_data + i);                
                    // printf("cpu Id: %d , ud[%d].counter : %d \r\n " , i,i,ud[i].counter);
            }

            printf("200 Status Count: %d\r",sum);
                    fflush(stdout);
        }
        // sleep(1);
    }
    printf("\n");
    close(map_fd);

    opts.flags = opts.prog_id = opts.prog_fd = 0;
    int dtch = bpf_tc_detach(&hook, &opts);
    int dstr = bpf_tc_hook_destroy(&hook);

    printf("%d -- %d\n", dtch, dstr);
    
    return 0;
}
