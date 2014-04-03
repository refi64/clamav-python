import clamav

x = clamav.engine() # create an engine instance
x.load_db() # load the database
x.compile() # compile the engine
print x.scanfile('/home/ryan/clamav-python/clamav.py') # scan the file
# the engine is automatically freed

