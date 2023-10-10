#include<iostream>
#include <vector>
#include <string>
#include <cstring>
using namespace std;

#define DEBUG_ 1

uint64_t str_to_long(char array[] ){

	// for(int i=0;i<8;i++)cout<<array[i];
	uint64_t value = 
	  static_cast<uint64_t>(array[0]) |
	  static_cast<uint64_t>(array[1]) << 8 |
	  static_cast<uint64_t>(array[2]) << 16 |
	  static_cast<uint64_t>(array[3]) << 24 |
	  static_cast<uint64_t>(array[4]) << 32 |
	  static_cast<uint64_t>(array[5]) << 40 |
	  static_cast<uint64_t>(array[6]) << 48 |
	  static_cast<uint64_t>(array[7]) << 56;
	  return value;
}

void printV(vector<uint64_t> v){
	cout<<"{ ";
	for(int i=0;i<v.size()-1;i++) cout<<v[i]<<',';
	cout<<v[v.size()-1];
	cout<<"}\n";
}

vector<vector<uint64_t>> genLong(string s){	
	
	uint64_t mask_set[]={0xFFFFFFFFFFFFFFFF, // all match
						 0x00000000000000FF, // 1 byte match
						 0x000000000000FFFF, // 2 byte match
						 0x0000000000FFFFFF, // 3 byte match
						 0x00000000FFFFFFFF, // 4 byte match
						 0x000000FFFFFFFFFF, // 5 byte match
						 0x0000FFFFFFFFFFFF, // 6 byte match
						 0x00FFFFFFFFFFFFFF, // 7 byte match
	};

	char * str  = (char *)s.c_str();
	int size = strlen(str);
	int u64_cnt = (size/8) + (size%8==0?0:1);
	int mask = size%8;
	int mask_loc = (mask==0?-1:u64_cnt-1);

	if(DEBUG_){
		cout<<"string:"<<s<<"\tsize:"<<size<<endl;
		cout<<"u64 required:"<<u64_cnt<<endl;
		cout<<"mask:"<<mask<<"\tmask loc:"<<mask_loc<<endl;
	}

	vector<uint64_t> out(u64_cnt,0); 
	vector<uint64_t> out_mask(u64_cnt,0); 

	for(int i =0 ;i<u64_cnt;i++){
		char* cptr = &str[i*8];
		out[i] = str_to_long(cptr);
		out_mask[i]=mask_set[0];
	}
	if(mask_loc!=-1)
		out_mask[mask_loc] = mask_set[mask];

	if(DEBUG_){
		cout<<"attr's"<<endl;
		printV(out);
	}

	if(DEBUG_){
		cout<<"msk's"<<endl;
		printV(out_mask);
	}	
	// for(int i=0;i<u64_cnt;i++)
	// 	cout<<(out_mask[i]&out[i])<<',';
	// cout<<endl;
	return {out,out_mask};	
}

void getLLforList(vector<string> list){
	vector<uint64_t> lvalues;
	vector<uint64_t> masks;

	for(string s : list){
		vector<vector<uint64_t>> slong = genLong(s);
		lvalues.push_back(slong[0][0]);
		masks.push_back(slong[1][0]);
	}
	cout<<"lvalues's"<<endl;
	printV(lvalues);

	cout<<"mask's"<<endl;
	printV(masks);
}

int main(){
	string s = "\"name\"";
	vector<string> attrlist= {"\"nam",
						 "\"cou",
						 "\"ins",
						 "\"id\"",
						 "\"cou",
						 "\"pro",
						 "\"cit",
						 "\"sta",
						};

//	getLLforList(attrlist);

	genLong("\"state\":\"ArunachalPradesh\"");
	return 0;	
}
