#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

#include "perfbuf.skel.h"
#include "common.h"

static volatile bool exiting = false;

/*Used to print error and information by libbpf as per the libbpf_print_level*/
int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	/* Ignore debug-level libbpf logs */
	if (level > LIBBPF_INFO)
		return 0;
	/*int vfprintf ( FILE * stream, const char * format, va_list arg );
		writes char * to the stream after inserting the args in the format*/
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
    exiting = true;
}


// static int handle_evt(void *ctx, void *data, size_t sz)
// {
//     return 0;
// }

void handle_evt(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s %-5s %-7d %-16s %s\n", ts, "EXEC", e->pid, e->comm, e->filename);
}


int main(int argc, char **argv)
{
	/* BPF CORE type of decleration for the backword comaptibility*/
	struct perf_buffer_opts pb_opts = {};
	struct perf_buffer *pb = NULL;
	struct perfbuf *skel;

	int err;

	/* Set up libbpf logging callback */
	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = perfbuf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint */
	err = perfbuf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	pb_opts.sample_cb = handle_evt;
	pb = perf_buffer__new(bpf_map__fd(skel->maps.pb), 8 /* 32KB per CPU */, &pb_opts);
	if (libbpf_get_error(pb)) {
		err = -1;
		fprintf(stderr, "Failed to create perf buffer\n");
		goto cleanup;
	}

	/* Process events */
	while (!exiting) {
		err = perf_buffer__poll(pb, 100 /* timeout, ms */);
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

cleanup:
	perf_buffer__free(pb);
	perfbuf__destroy(skel);
	return 0;
}

