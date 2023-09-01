#ifndef __SC_H__
#define __SC_H__

#define MAX_ENTRIES 1
#define COUNTER_KEY 0
#define INIT_COUNTER 1

#define DEBUG_LEVEL_2 0
#define DEBUG_LEVEL_1 0

#define BPF_ANY 0
typedef struct user_data{
	int counter;
}ud_t;	

struct bpf_info{
	int count;
};


#endif //__SC_H__