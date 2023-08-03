#ifndef __TC_PERH_H
#define __TC_PERH_H

#define MAX_SIZE 1400

/* definition of a sample sent to user-space from BPF program */
struct event {
	char payload[MAX_SIZE];
};

#endif /* __TC_PERH_H */
