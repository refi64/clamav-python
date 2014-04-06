from ctypes.util import find_library
import sys, os, cffi

if sys.version_info[0] == 3:
    def _reraise(ex):
        raise ex[1].with_traceback(ex[2])
else:
    exec('''
def _reraise(ex):
    raise ex[1], None, ex[2]
    ''')

_pre_callback_base = ['int', 'const char*', 'void*']
_callback_str = lambda c: 'int(%s)' % (', '.join(c))
_callback_ffi = lambda c, n: 'int (*%s)(%s)' % (n, ','.join(c))

__version__ = 0.2

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

typedef %s;

void cl_engine_set_clcb_pre_scan(void*, clcb_pre_scan);
''' % (_callback_ffi(_pre_callback_base, 'clcb_pre_scan')))

_bases = {'pre_scan': _pre_callback_base}

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

result = {'clean': 0, 'virus': 1, 'break': 22}

class ClamavError(Exception):
    def __init__(self, errcode, errstr):
        self.errcode = errcode
        super(ClamavError, self).__init__(errstr)

class engine(object):
    def __init__(self, dll_path=find_library('clamav'), init_code=0x0):
        self.exc = None
        self.dll = ffi.dlopen(dll_path)
        self.engine = self.dll.cl_engine_new()
        self.callbacks = {'pre_scan': None, 'post_scan': None}
        self.c_callbacks = self.callbacks
    def load_db(self, dbdir=None, options=dbopt['stdopt']):
        if not dbdir:
            dbdir = self.dll.cl_retdbdir()
        csigs = ffi.new('unsigned int*')
        ret = self.dll.cl_load(dbdir, self.engine, csigs, options)
        if ret != 0:
            raise ClamavError(ret, self.dll.strerror(ret))
        return csigs[0]
    def compile(self):
        # register callbacks
        for k,v in self.callbacks.items():
            if v is not None:
                getattr(self.dll, 'cl_engine_set_clcb_%s' %  k)(self.engine, self.c_callbacks[k])
        self.dll.cl_engine_compile(self.engine)
    def scanfile(self, filename, options=scanopt['stdopt']):
        fname = ffi.new('const char[]', filename.encode())
        cvir = ffi.new('const char**')
        ret = self.dll.cl_scanfile(fname, cvir, ffi.NULL, self.engine, options)
        if self.exc is not None:
            _reraise(self.exc)
        if ret == result['clean']:
            return None
        elif ret == result['virus']:
            return ffi.string(cvir[0])
        else:
            raise ClamavError(ret, ffi.string(self.dll.cl_strerror(ret)))
    def _get_callback(self, n): return self.callbacks[n]
    def _set_callback(self, f, n, first_fd=True):
        def _call(*args):
            call_args = [os.fdopen(args[0])] if first_fd else []
            try:
                res = f(*call_args)
                if res is None:
                    res = result['clean']
                if res not in result:
                    raise ClamavError()
            except ClamavError:
                return result['break']
            except:
                self.exc = sys.exc_info()
                return result['break']
            return res
        self.callbacks[n] = _call
        self.c_callbacks[n] = ffi.callback(_callback_str(_bases[n]), _call)
    @property
    def pre_scan_callback(self): return self._get_callback('pre_scan')
    @pre_scan_callback.setter
    def pre_scan_callback(self, f): self._set_callback(f, 'pre_scan')
    def __del__(self):
        if hasattr(self, 'engine'):
            self.dll.cl_engine_free(self.engine)
