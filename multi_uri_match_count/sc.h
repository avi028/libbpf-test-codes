#ifndef __SC_H__
#define __SC_H__

// config
#define PORT 80
#define INTERFACE_NAME "lo"

// debug levels
#define DEBUG_LEVEL_2 0
#define DEBUG_LEVEL_1 1


// map related config
#define MAX_ENTRIES 1
#define MAX_URI_MAP_ENTRIES 10

#define COUNTER_KEY 0
#define URI_KEY 0

#define BPF_ANY 0
typedef struct user_data{
	int counter;
}ud_t;	

// typedef struct uri_map{
// 	char uri[18];
// }uri_map_t;

struct bpf_info{
	int count;
};


#endif //__SC_H__