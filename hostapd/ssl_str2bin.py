#!/usr/bin/python
#coding:utf-8
import binascii
import sys

data_from_hostapd = '''
01 00 00 7e f4 1a cf db c8 e7 4f 5f 6c 53 63 42 36 08 b4 c4 01 0b 61 6e 6f 6e 79 6d 6f 75 73 04 06 7f 00 00 01 1f 13 30 32 2d 30 30 2d 30 30 2d 30 30 2d 30 30 2d 30 31 0c 06 00 00 05 78 3d 06 00 00 00 13 4d 18 43 4f 4e 4e 45 43 54 20 31 31 4d 62 70 73 20 38 30 32 2e 31 31 62 4f 10 02 00 00 0e 01 61 6e 6f 6e 79 6d 6f 75 73 50 12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
'''

def hex_two_byte_to_buf(str):
    return reduce(lambda x, y: x + y, map(lambda x: binascii.a2b_hex(x), str.split()))

def sslstr_to_sslbin():
    ''' read '''
    try:
        f = open("./py_client_hello1","r")  
        lines = f.readlines()#读取全部内容  
        #print lines
        if len(lines) != 1: 
            print 'line > 1'
            sys.exit()
        data_from_file = lines[0].split('\n')[0]
        print data_from_file
        buff = hex_two_byte_to_buf(data_from_file)
        print buff.encode('hex')
    finally:
        f.close()

    ''' write '''
    try:
        f = open("./c_client_hello1","w")  
        f.write(buff)
    finally:
        f.close()

if __name__ == "__main__":
    sslstr_to_sslbin()
