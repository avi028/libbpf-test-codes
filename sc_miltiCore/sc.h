#ifndef __SC_H__
#define __SC_H__

#define MAX_ENTRIES 2
#define COUNTER_KEY 1
#define BPF_ANY 0
typedef struct user_data{
	int counter;
}ud_t;	

struct bpf_info{
	int count;
};


#endif //__SC_H__