import os

key_list = ["name", "country", "institute", "id", "course", "program", "city", "state"]
file = "./exp1.txt"
const_attribute = '"state":"ArunachalPradesh"'

# 13-200 70-600 127-1000 185-1404
attr_list = [4,6,8,10]
payload_sizes = [200,600,1000,1400]

if __name__ == "__main__":
    prefix = "data2_"
    for itr in range(0,4):
        file = prefix + str(attr_list[itr]) + ".txt"
        f = open(file, "w")
        f.write("{")
        init_len=1
        payload_size = 1473
        attr_num = attr_list[itr]
        value_size = (payload_size - len(const_attribute))/(attr_num-1)  - 14
        for i in range(0,attr_num):    
            if i == attr_num-1:
                f.write(const_attribute+"}")
                init_len+=len(const_attribute)+1
            else:
                s = '"' + 'a'*7 + chr(97+i) + '":"' + '1'*value_size+'",'
                f.write(s)    
                init_len+=len(s)
                skip_bytes=init_len
        print("skip bytes : " + str(skip_bytes))
        print("data file : " + file)
        f.write('#'*(payload_size-init_len))
