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
#include <bpf/libbpf.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "tc_perf.h"
#include "tc_perf.skel.h"


static volatile bool exiting = false;

/*Used to print error and information by libbpf as per the libbpf_print_level*/
/*int vfprintf ( FILE * stream, const char * format, va_list arg ); writes char * to the stream after inserting the args in the format*/
int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	/* Ignore debug-level libbpf logs */
	if (level > LIBBPF_INFO)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
    exiting = true;
}

int counter = 0;

void handle_evt(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	const struct event *e = data;

	long unsigned int n = sizeof(e->payload);
	struct http_response *h = (struct http_response *) ((void*)(e->payload));

	// check http and status code 
	//&& h->scode[0]=='2' && h->scode[1]=='0' && h->scode[2]=='0'
	if(h->http[0]=='H' && h->http[1]=='T' && h->http[2]=='T' && h->http[3]=='P'){
		int flag = 0 ;	
		int http_header_len = 0;		
		for(int i =0 ;i<n-3;i++){
			http_header_len++;
			if(e->payload[i]=='\r' && e->payload[i+1]=='\n' && e->payload[i+2]=='\r' && e->payload[i+3]=='\n'){
				flag=1;
				break;
			}
		}

		http_header_len+=3;
		if(flag==1)
			for(int i = http_header_len ; i< n ;i ++){
				// if(e->payload[i]==1)
					flag=-1;
			}

		if(flag == -1){
			counter++;			
		}
	}
}

long long timeInMilliseconds(void) {
    struct timeval tv;

    gettimeofday(&tv,NULL);
    return (((long long)tv.tv_sec)*1000)+(tv.tv_usec/1000);
}

// ifindex 1 -> loopback
// ifindex 2 -> ethernet
// ifindex 3 -> wifi

int main(int argc, char **argv)
{
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = 4, .attach_point = BPF_TC_INGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .handle = 1, .priority = 1);

	struct perf_buffer_opts pb_opts = {};
	struct perf_buffer *pb = NULL;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct tc_perf *skel = tc_perf__open_and_load();

    if(skel == NULL)
    {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    printf("Program Loaded\n");

    bpf_tc_hook_create(&hook);

    hook.attach_point = BPF_TC_CUSTOM;
    hook.parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS);

    opts.prog_fd = bpf_program__fd(skel->progs.perf_packet);
    opts.prog_id = 0; 
    opts.flags = BPF_TC_F_REPLACE;
    
    int err = bpf_tc_attach(&hook, &opts);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto  EXIT;
	}

    printf("Program Attached\n");

	/* Set up ring buffer polling */
	pb_opts.sample_cb = handle_evt;
	pb = perf_buffer__new(bpf_map__fd(skel->maps.pb), 8 /* 32KB per CPU */, &pb_opts);
	if (libbpf_get_error(pb)) {
		err = -1;
		fprintf(stderr, "Failed to create perf buffer\n");
		goto EXIT;
	}

	long long nextPrint = timeInMilliseconds()+2000;
	/* Process events */
	while (!exiting) {
		err = perf_buffer__poll(pb, 1/* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
		// long long current = timeInMilliseconds();
		// if(current>nextPrint){
		// 	printf("200 Status Count at: %d\r",counter);
        //     fflush(stdout);
		// 	nextPrint = current+2000;
		// }
	}

	printf("200 Status Count at: %d\r",counter);
	fflush(stdout);

	EXIT: 

    opts.flags = opts.prog_id = opts.prog_fd = 0;
	perf_buffer__free(pb);
    int dtch = bpf_tc_detach(&hook, &opts);
    int dstr = bpf_tc_hook_destroy(&hook);
    printf("%d -- %d\n", dtch, dstr);

	tc_perf__destroy(skel);    
    return 0;
}
