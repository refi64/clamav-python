#!/usr/bin/env python
import clamav

def pre_scan(f, t):
    print(f.read())
    print(t)

def post_scan(r, v):
    print(r, v)

x = clamav.engine() # create an engine instance
x.load_db() # load the database
x.pre_scan_callback = pre_scan
x.post_scan_callback = post_scan
x.compile() # compile the engine
print(x.scanfile('clamav.py')) # scan the file
# the engine is automatically freed
