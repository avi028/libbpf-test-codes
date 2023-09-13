#include<iostream>
#include <vector>
#include <string>
#include <random>
#include <ctime>
#include <unordered_set>

using namespace std;

#define KEY_SET_SIZE 30

/* 
	Uncomment below line for Variable location 
*/
// #define VAR_LOCATION

/* 
	Uncomment below line for variable imn key size
*/
#define VAR_VALUE_SIZE

int main(){

	#ifdef VAR_VALUE_SIZE
		cerr<<"VAR_VALUE_SIZE\n";
		string key_set [KEY_SET_SIZE] = {"12345677890","3234","d43r55","3325fg43tedsfr43","355423fef4yj567",
							 "o4i5f430g","fh32rh3rsdsna90hr", "23823hf02h3f","34fh2cg89h9bsad4jg90jf2","492hdk2=sadsada3jf8943h",
							"123477890","3254","d47r55","3325fgedsfr43","5354yj567",
							 "o4i5as430g","fhrh3rsdsna90hr", "23823hasdsadf02h3f","34fh2cg8bsad4jg90jf2","49a3jf8943h",
							"345677890","3834","g13r55","332tedsfr43","355423fsadasdef4yj567",
							 "o4i5g430g","fh323rsdsnasads90hr", "02h3f","3cdfdsag89h9bsad4jg90jf2","fegasdegadsad3jf8943h"};

	#else
		string key_set[KEY_SET_SIZE] = {"21fgh","h1dst","78fbs","62gdf","hj4td","siq2r","bhefk","56432","0ihdt","7gald",
							"22ash","htdst","78fas","67g4f","hjvtd","s7qdr","bvefk","52432","1ihdt","7gcld",
							"23vsd","hqwst","78fqw","17gdf","hjatd","6iqdr","2befk","57432","3ihdt","7gvld"};
	#endif


	string attr_set [26];
	unordered_set<int> marked_keys;
	srand(time(0));

	// attr generation 
	attr_set[0]="a";
	for(int i=1;i<26;i++){
		attr_set[i] = attr_set[i-1]+(char)('a'+i);
	}

	vector<string> final_out;
	for(string attr : attr_set){
		int key_itr=(rand())%KEY_SET_SIZE;
		while(marked_keys.find(key_itr)!=marked_keys.end()){
			key_itr=(rand())%KEY_SET_SIZE;
		}
		marked_keys.insert(key_itr);
		final_out.push_back("\""+attr+"\":\""+key_set[key_itr]+"\",");
	}

	cout<<"{";

	#ifdef VAR_LOCATION
		cerr<<"VAR_LOCATION\n";

		unordered_set<int> marked_finals;
		srand(time(0));

		while(marked_finals.size()<26){
			int itr = rand()%26;
			while(marked_finals.find(itr)!=marked_finals.end())
				itr = rand()%26;
			marked_finals.insert(itr);
			cout<<final_out[itr];
		}

	#else

		for(string out : final_out)
			cout<<out;

	#endif
	
	cout<<"}";

	return 0;
}