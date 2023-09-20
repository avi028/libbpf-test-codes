#include<iostream>
#include <vector>
#include <string>

using namespace std;

uint64_t str_to_long(char array[] ){
	for(int i=0;i<8;i++)cout<<array[i];
	uint64_t value = 
	  static_cast<uint64_t>(array[0]) |
	  static_cast<uint64_t>(array[1]) << 8 |
	  static_cast<uint64_t>(array[2]) << 16 |
	  static_cast<uint64_t>(array[3]) << 24 |
	  static_cast<uint64_t>(array[4]) << 32 |
	  static_cast<uint64_t>(array[5]) << 40 |
	  static_cast<uint64_t>(array[6]) << 48 |
	  static_cast<uint64_t>(array[7]) << 56;
	  cout<<" -> "<<value<<endl;
	  return value;
}


char str [] = "dkniendeifnewifiabcsedfq\"";

int main(){

	cout<<str<<endl;
	int size = sizeof(str)-1;
	cout<<"size "<<size<<endl;
	int u64_cnt = (size/8) + (size%8==0?0:1);
	int mask = size%8;
	int mask_loc = (mask==0?-1:u64_cnt-1);

	cout<<"u64 required "<<u64_cnt<<endl;

	cout<<"mask "<<mask<<" mask loc "<<mask_loc<<endl;
	uint64_t m = 0xFFFFFFFFFFFFFFFF;
	uint64_t out_mask[u64_cnt	]; 
	uint64_t out[u64_cnt];
	uint64_t mask_set[]={0xFFFFFFFFFFFFFFFF, // all match
						 0x00000000000000FF, // 1 byte match
						 0x000000000000FFFF, // 2 byte match
						 0x0000000000FFFFFF, // 3 byte match
						 0x00000000FFFFFFFF, // 4 byte match
						 0x000000FFFFFFFFFF, // 5 byte match
						 0x0000FFFFFFFFFFFF, // 6 byte match
						 0x00FFFFFFFFFFFFFF, // 7 byte match
	};

	for(int i =0 ;i<u64_cnt;i++){
		char* cptr = &str[i*8];
		out[i] = str_to_long(cptr);
		out_mask[i]=mask_set[0];
	}
	if(mask_loc!=-1)
		out_mask[mask_loc] = mask_set[mask];
	cout<<"{ ";
	for(uint64_t o : out) cout<<o<<',';
	cout<<"}\n";

	cout<<"{ ";
	for(uint64_t o : out_mask) cout<<o<<',';
	cout<<"}\n";
	
	for(int i=0;i<u64_cnt;i++)
		cout<<(out_mask[i]&out[i])<<',';
	cout<<endl;

	return 0;	
}