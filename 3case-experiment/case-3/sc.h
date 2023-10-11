#ifndef __SC_H__
#define __SC_H__

// expriment realted constants
#define SINGLE_CORE 1
#define MULTI_CORE 2

// config
#define MTU_SIZE 1500
#define PORT 80
#define INTERFACE_NAME "lo"
#define BYTE_PEEKS MTU_SIZE

// debug levels
#define DEBUG_LEVEL_2 0
#define DEBUG_LEVEL_1 0

//experiment realted config
#define CORES SINGLE_CORE

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