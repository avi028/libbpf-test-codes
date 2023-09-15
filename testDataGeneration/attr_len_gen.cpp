#include<iostream>
#include <vector>
#include <string>

using namespace std;


uint64_t str_to_long(){
	unsigned char array[8] = { 	'"',
								'a',
								'"',
								':',
								'"',
								'4',
								'9',
								'2',};
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

int main(){

	cout<<str_to_long()<<endl;
	return 0;	
}