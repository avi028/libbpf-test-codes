#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdint.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netdb.h>
#include <linux/pkt_cls.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/msg.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "tc_perf_ipc.h"
#include "tc_perf_ipc.skel.h"


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

    struct msgIPCbuf msg;
    msg.mtype=1;
    strcpy(msg.payload,e->payload);

    int status; 
	status= msgsnd(msgId,&msg,sizeof(msg.payload),0);
    if(status == -1){
        perror("msg send error");
        exit(EXIT_FAILURE);
    }
}


// ifindex 1 -> loopback
// ifindex 2 -> ethernet
// ifindex 3 -> wifi


void logger(){

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct msgIPCbuf msgC;
    printf("Logger: waiting for msg\n");

    while(!exiting){

	    int status =msgrcv(msgId,&msgC,sizeof(msgC.payload),1,0);
	    if(status == -1){
	        perror("No msg received");
	    }
	    else{

			long unsigned int n = sizeof(msgC.payload);
			struct http_response *h = (struct http_response *) ((void*)(msgC.payload));

			if(h->http[0]=='H' && h->http[1]=='T' && h->http[2]=='T' && h->http[3]=='P'){
				int flag = 0 ;	
				int http_header_len = 0;		
				for(int i =0 ;i<n-3;i++){
					http_header_len++;
					if(msgC.payload[i]=='\r' && msgC.payload[i+1]=='\n' && msgC.payload[i+2]=='\r' && msgC.payload[i+3]=='\n'){
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
		            printf("200 Status Count at: %d\r",counter);
		            fflush(stdout);
				}
			}
	    }
    }

}

void driver_code(){

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = 1, .attach_point = BPF_TC_EGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .handle = 1, .priority = 1);

	struct perf_buffer_opts pb_opts = {};
	struct perf_buffer *pb = NULL;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct tc_perf_ipc *skel = tc_perf_ipc__open_and_load();

    if(skel == NULL)
    {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return;
    }

    printf("Program Loaded\n");

    bpf_tc_hook_create(&hook);

    hook.attach_point = BPF_TC_CUSTOM;
    hook.parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);

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
	}


	EXIT: 

    opts.flags = opts.prog_id = opts.prog_fd = 0;
	perf_buffer__free(pb);
    int dtch = bpf_tc_detach(&hook, &opts);
    int dstr = bpf_tc_hook_destroy(&hook);
    printf("%d -- %d\n", dtch, dstr);
	msgctl(msgId,IPC_RMID,0);
	tc_perf_ipc__destroy(skel);    	
}

int main(int argc, char **argv)
{
    msgId = msgget(msg1,IPC_CREAT|0666);
 
    if(msgId==-1)
    {
        perror("Cannot get msg id ");
        exit(0);
    }
    
    int id = fork();
    
    if(id==0){
    	logger();
    }
    else{
    	driver_code();
    }
    return 0;
}
