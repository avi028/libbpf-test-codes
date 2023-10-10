import os

key_list = ["name", "country", "institute", "id", "course", "program", "city", "state"]
file = "./exp1.txt"
const_attribute = '"state":"ArunachalPradesh"'

# 13-200 70-600 127-1000 185-1404
val_size_list = [13,70,127,185]
payload_size = [200,600,1000,1400]

if __name__ == "__main__":
    prefix = "data_"
    for i in range(0,4):
        file = prefix + str(payload_size[i]) + ".txt"
        f = open(file, "w")
        f.write("{")
        init_len=1
        value_size = val_size_list[i]
        
        for i in key_list:    
            if i == key_list[len(key_list) - 1]:
                f.write(const_attribute+"}")
                init_len+=len(const_attribute)+1
            else:
                s = '"' + i + '":"' + '1'*value_size+'",'
                f.write(s)    
                init_len+=len(s)
                skip_bytes=init_len
        print("skip bytes : " + str(skip_bytes))
        print("data file : " + file)
        f.write('#'*(1420-init_len))
