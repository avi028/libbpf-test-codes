#ifndef __SC_H__
#define __SC_H__

#define MAX_U32_DIGITS 10 //2^32-1 --> 4294967295

// expriment realted constants
#define SINGLE_CORE 1
#define MULTI_CORE 2
#define ARRAY 1
#define HASHMAP 2

// config
// #define PORT 80
#define PORT 5000
// #define INTERFACE_NAME "lo"
#define INTERFACE_NAME "ens259f1"

// map related config
#define STORAGE_SIZE 1<<9 //bytes range to wary for exerpiment 64(1<<6) 128(1<<7) 256(1<<8) 512(1<<9) 
#define KEY_SIZE 2 //bytes
#define MAX_ENTRIES 1<<4// count of entries

// 1<<26 is the hard limit : 64 MB for key size * value size

//experiment realted config
#define CORES SINGLE_CORE
#define MAP_TYPE ARRAY

#define COUNTER_KEY 0 

// debug levels
#define DEBUG_LEVEL_2 0
#define DEBUG_LEVEL_1 0

// Uncomment it for multicore 
// #define MULTI_CORE

// defines not found in vmlinux.h
#define BPF_ANY 0

// // count value 
// typedef struct user_data{
// 	int counter;
// }ud_t;	

// storage test map
typedef struct map_data{
	 uint8_t value[STORAGE_SIZE];
}map_value_t;

typedef struct map_key{
	 uint8_t key[KEY_SIZE];
}map_key_t;


#endif //__SC_H__