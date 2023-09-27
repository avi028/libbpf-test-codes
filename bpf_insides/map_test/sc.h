#ifndef __SC_H__
#define __SC_H__

#define MAX_U32_DIGITS 10 //2^32-1 --> 4294967295

// expriment realted constants
#define SINGLE_CORE 1
#define MULTI_CORE 2
#define ARRAY 1
#define HASHMAP 2

// config
#define PORT 80
#define INTERFACE_NAME "lo"

// map related config
#define STORAGE_SIZE 5 // bytes
#define KEY_SIZE 2 //bytes
#define MAX_ENTRIES 64 // count of entries

//experiment realted config
#define CORES SINGLE_CORE
#define MAP_TYPE ARRAY

#define COUNTER_KEY 0 

// debug levels
#define DEBUG_LEVEL_2 0
#define DEBUG_LEVEL_1 1

// Uncomment it for multicore 
// #define MULTI_CORE

// defines not found in vmlinux.h
#define BPF_ANY 0

// count value 
typedef struct user_data{
	int counter;
}ud_t;	

// storage test map
typedef struct map_data{
	 uint8_t value[STORAGE_SIZE];
}map_value_t;

typedef struct map_key{
	 uint8_t key[KEY_SIZE];
}map_key_t;


#endif //__SC_H__