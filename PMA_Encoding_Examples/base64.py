import binascii
import string
from numpy import std
import pybase64


def base64fun(ex_str):
    ex_str = str.encode(ex_str)
    print(pybase64.b64encode(ex_str))

# base64fun("just a test string ")


def custombase64(cipher , custom):
    s=""
    std_base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    for i in cipher:
        if i in std_base64:
            s += std_base64[custom.find(str(i))]
        elif i == "=":
            s+= "="
    
    return pybase64.b64decode(s)
    
# print(custombase64("TEgobxZobxZgGFPkb2O=","9ZABCDEFGHIJKLMNOPQRSTUVWXYabcdefghijklmnopqrstuvwxyz012345678+/"))


def xorfun(ex_str,key):
    res=[]
    for i in ex_str:
        if ord(i) != ord(" ") and i !=str(key):
            res.append(chr(ord(i)^key))
        else:
            res.append(i)

    return ''.join(res)

# print(xorfun("d d ddd",12))


