key_list = ["name", "country", "institute", "id", "course", "program", "city", "state"]


if __name__ == "__main__":
    f = open("exp1.json", "w")
    f.write("{")
    value_size = 10
    
    for i in key_list:
        f.write('"' + i + '": "')
        for j in range(1, value_size):
            f.write("1")
        if i == key_list[len(key_list) - 1]:
            f.write('"}')
        else:
            f.write('",')