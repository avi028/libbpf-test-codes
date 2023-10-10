#ifndef __SC_H__
#define __SC_H__

// expriment realted constants
#define SINGLE_CORE 1
#define MULTI_CORE 2

// config
#define PORT 5000
#define INTERFACE_NAME "lo"

//experiment realted config
#define CORES SINGLE_CORE

// debug levels
#define DEBUG_LEVEL_2 0
#define DEBUG_LEVEL_1 1

// Uncomment it for multicore 
// #define MULTI_CORE

// defines not found in vmlinux.h
#define BPF_ANY 0

// map related config
#define MAX_ENTRIES 2
#define COUNTER_KEY 0

// map value 
typedef struct user_data{
	int counter;
}ud_t;	


#endif //__SC_H__