#ifndef __SC_H__
#define __SC_H__

#define COUNTER_KEY 1234

typedef struct user_data{
	int counter;
}ud_t;	

struct bpf_info{
	int count;
};


#endif //__SC_H__