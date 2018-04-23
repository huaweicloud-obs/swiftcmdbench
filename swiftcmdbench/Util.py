# -*- coding:utf-8 -*-
from random import Random
import base64
import hmac
import hashlib
import logging

import random

TIME_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'
ISO8601 = '%Y%m%dT%H%M%SZ'
ISO8601_MS = '%Y-%m-%dT%H:%M:%S.%fZ'
RFC1123 = '%a, %d %b %Y %H:%M:%S %Z'

def random_string_create(string_length):  
    random_string = ''  
    chars_all = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789'
    random = Random()
    if isinstance(string_length,int):
        i = 0 
        while i < string_length:  
            random_string+=chars_all[random.randint(0, int(len(chars_all) - 1))]
            i = i + 1
        return random_string
    else:
        print 'input error'

#返回对象大小，和是否是固定值，可必免反复请求。ifFixed = True
def generate_a_size(dataSizeStr):
    random = Random()
    if str(dataSizeStr).find('~') != -1:
            startSize = int(dataSizeStr.split('~')[0])
            endsize = int(dataSizeStr.split('~')[1])
            return random.randint(startSize, endsize),False
    elif str(dataSizeStr).find(',') != -1:
            sizeArray = dataSizeStr.split(',')
            return int(sizeArray[random.randint(0, len(sizeArray) -1 )]),False
    else: return int(dataSizeStr),True
    
def get_utf8_value(value):
    if not value: return ''
    if isinstance(value, str):
        return value
    if isinstance(value, unicode):
        return value.encode('utf-8')
    return str(value)

def compareVersion(v1, v2):
    v1 = v1.split('.')
    v2 = v2.split('.')
    try:
        for i in range(0, len(v1)):
            if len(v2) < i+1:
                return 1
            elif int(v1[i]) < int(v2[i]):
                return -1
            elif  int(v1[i]) > int(v2[i]):
                return 1
    except:
           return -1
    if len(v2) > len(v1): return -1
    return 0

