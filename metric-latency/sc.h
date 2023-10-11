#ifndef __SC_H__
#define __SC_H__

#define COUNTER_KEY 1
#define BPF_ANY 0
typedef struct user_data{
	u_int64_t counter;
	u_int64_t timestamp;
}ud_t;	

struct bpf_info{
	int count;
};


#endif //__SC_H__