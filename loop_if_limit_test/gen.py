str1 = "if(((void*)data +"
str2=" + sizeof(*cptr)) <= data_end ){ cptr = (struct c1 *)(data + "
str3=" ); if(cptr->c[0]=='1') flag+=1; } "

for i in range(500):
	print(str1+str(i)+str2+str(i)+str3)