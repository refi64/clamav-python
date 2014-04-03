from ctypes.util import find_library
import cffi

__version__ = 0.1

ffi = cffi.FFI()

ffi.cdef('''
void cl_init(unsigned int);
const char* cl_retdbdir(void);
const char* cl_strerror(unsigned int);
void* cl_engine_new();
int cl_load(const char*, int*, unsigned int*, unsigned int);
int cl_engine_free(void*);
void cl_engine_compile(void*);
int cl_scanfile(const char*, const char**, unsigned long*, void*, unsigned int);
''')

dbopt = {'phishing': 0x2,
         'phishing_urls': 0x8,
         'pua': 0x10,
         'pua_mode': 0x80,
         'pua_include': 0x100,
         'pua_exclude': 0x200,
         'official_only': 0x1000,
         'bytecode': 0x2000,
         'bytecode_unsigned': 0x8000,
         'stdopt': 0x2|0x8|0x2000}

scanopt = {'raw': 0x0,
           'archive': 0x1,
           'mail': 0x2,
           'ole2': 0x4,
           'blockencrypted': 0x8,
           'html': 0x10,
           'pe': 0x20,
           'blockbroken': 0x40,
           'algorithmic': 0x200,
           'phishing_blockssl': 0x800,
           'phishing_blockcloak': 0x1000,
           'elf': 0x2000,
           'pdf': 0x4000,
           'structured': 0x8000,
           'structured_ssn_normal': 0x10000,
           'scructured_ssn_stripped': 0x20000,
           'partial_message': 0x40000,
           'heuristic_precedence': 0x80000,
           'blockmacros': 0x100000,
           'stdopt': 0x1|0x2|0x4|0x4000|0x10|0x20|0x200|0x2000}

class ClamavError(Exception):
    def __init__(self, errcode, errstr):
        self.errcode = errcode
        self.errstr = errstr
    def __str__(self):
        return self.errstr
    def __repr__(self):
        return 'ClamavScanError(\'%s\')' % self.errstr

class engine(object):
    def __init__(self, dll_path=find_library('clamav'), init_code=0x0):
        self.dll = ffi.dlopen(dll_path)
        self.engine = self.dll.cl_engine_new()
    def load_db(self, dbdir=None, options=dbopt['stdopt']):
        if not dbdir:
            dbdir = self.dll.cl_retdbdir()
        csigs = ffi.new('unsigned int*')
        ret = self.dll.cl_load(dbdir, self.engine, csigs, options)
        if ret != 0:
            raise ClamavError(ret, self.dll.strerror(ret))
        return csigs[0]
    def compile(self):
        self.dll.cl_engine_compile(self.engine)
    def scanfile(self, filename, options=scanopt['stdopt']):
        fname = ffi.new('const char[]', filename)
        cvir = ffi.new('const char**')
        ret = self.dll.cl_scanfile(fname, cvir, ffi.NULL, self.engine, options)
        if ret == 0:
            return None
        elif ret == 1:
            return ffi.string(cvir[0])
        else:
            raise ClamavError(ret, self.dll.strerror(ret))
    def __del__(self):
        if hasattr(self, 'engine'):
            self.dll.cl_engine_free(self.engine)

