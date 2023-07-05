#ifndef __SC_H__
#define __SC_H__

typedef struct user_data{
	char s[100];
	char p[10];
	int pt[10];
	int p_len;
	int s_len;
}ud_t;	

struct bpf_info{
	int count;
};


#endif //__SC_H__