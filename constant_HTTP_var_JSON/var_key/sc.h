#ifndef __SC_H__
#define __SC_H__

// config
#define PORT 80
#define INTERFACE_NAME "lo"

// debug levels
#define DEBUG_LEVEL_2 0
#define DEBUG_LEVEL_1 1

// defines not found in vmlinux.h
#define BPF_ANY 0

// map related config
#define MAX_ENTRIES 64
#define COUNTER_KEY 0

// map value 
typedef struct user_data{
	int counter;
}ud_t;	


#endif //__SC_H__