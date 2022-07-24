
s=[]

with open("Lab12-02.bin",'rb') as f:
    buff = f.read()
    for i in range(len(buff)):
        s.append(buff[i] ^ 0x41 )

# print(s)
with open("Lab_out.bin",'wb') as f:
    for i in s:

        f.write(bytes((i,)))