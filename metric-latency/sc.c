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
#include <time.h>

#include "sc.h"
#include "sc.skel.h"

static volatile bool exiting = false;

#define DISTRIBUTION_SIZE 5000
u_int64_t packet_counter = 0;
double total_delay = 0;
u_int64_t delay_counter = 0;
u_int64_t delays_dist[DISTRIBUTION_SIZE];
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
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = 5, .attach_point = BPF_TC_INGRESS);
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
	struct timespec currentTime;

    bpf_map_update_elem(map_fd,&key,&ud,BPF_ANY);

    while(exiting!=true){
        int status = bpf_map_lookup_elem(map_fd,&key,&ud);
        // printf("map status %d", status);
        if(status!=-1){
            if(ud.counter != packet_counter){
                clock_gettime(CLOCK_MONOTONIC, &currentTime);
                int64_t latency = (currentTime.tv_sec*1000000000+currentTime.tv_nsec - ud.timestamp)/1000;
                total_delay += latency;
                delay_counter++;
                
                if(latency<0)
                    delays_dist[0]++;
                else if(latency<DISTRIBUTION_SIZE)
                    delays_dist[latency]++;

            }
            packet_counter = ud.counter;
            printf("200 Status Count: %lu\r",ud.counter);
            fflush(stdout);
        }
        usleep(100);
    }
    printf("\n");

    printf("\nNo of packets received: %lu\n", packet_counter);
	if(delay_counter==0){
		fflush(stdout);
		exit(0);
	}

    printf("\nNo of packets sampled: %lu\n", delay_counter);
	printf("\nTotal Delay: %.0lf(in us), Average Delay: %.3lf(in us)\n", total_delay, total_delay/delay_counter);
	printf("\nDelays (in us), No of Packets, Percentile,\n");

	uint64_t counter = 0;
	float percentile = 0;
	for(int delay = 0; delay<DISTRIBUTION_SIZE; delay++){
		if(delays_dist[delay]>0){
			counter += delays_dist[delay];
			percentile = (float)counter*100/delay_counter;
			printf("%14u,%14lu,%11.3f,\n", delay, delays_dist[delay], percentile);		}
	}
	if(delay_counter-counter>0)
		printf(">=%12u,%14lu,%11.3f,\n", DISTRIBUTION_SIZE, delay_counter-counter, 100.0);

	fflush(stdout);

    close(map_fd);

    opts.flags = opts.prog_id = opts.prog_fd = 0;
    int dtch = bpf_tc_detach(&hook, &opts);
    int dstr = bpf_tc_hook_destroy(&hook);

    printf("%d -- %d\n", dtch, dstr);
    
    return 0;
}
