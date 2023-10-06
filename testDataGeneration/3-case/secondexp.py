#key_list = ["name", "country", "institute", "id", "course", "program", "city", "state"]


if __name__ == "__main__":
    f = open("exp2.json", "w")
    f.write("{")
    payload_size = 100
    attr_num = 4
    value_size = payload_size - attr_num * 14

    for i in range(1, attr_num):
        if i == attr_num - 1:
            f.write('"state":"')
        else:
            f.write('"' + "aaaaaaa" + chr(97+i) + '":"')
        for j in range(1, value_size):
            f.write("1")
        if i == attr_num - 1:
            f.write('"}')
        else:
            f.write('",')