#!/usr/bin/env python
import clamav

def pre_scan(f): print(f.read())

x = clamav.engine() # create an engine instance
x.load_db() # load the database
x.pre_scan_callback = pre_scan
x.compile() # compile the engine
print(x.scanfile('clamav.py')) # scan the file
# the engine is automatically freed
