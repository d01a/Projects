x="4tq2sI0ee2oQ`44v1se"
res=""
for i in range(19):
    if ord(x[i])%2==0:
        res += chr(ord(x[i])+1)
    else:
        res += chr(ord(x[i])-1)
print(res) 