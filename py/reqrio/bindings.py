import os
import sys
from ctypes import cdll, CFUNCTYPE, c_void_p, c_int, c_char, c_uint32, c_char_p

from _ctypes import POINTER

base = os.path.dirname(__file__)
if sys.platform == 'win32':
    dll_path = os.path.join(base, 'reqrio.dll')
elif sys.platform == 'linux':
    dll_path = os.path.join(base, 'libreqrio.so')
else:
    raise Exception('unsupported platform')
DLL = cdll.LoadLibrary(dll_path)

# 初始化函数
DLL.init_http.restype = c_int

DLL.set_header_json.argtypes = [c_int, c_char_p]
DLL.set_header_json.restype = c_int

DLL.add_header.argtypes = [c_int, c_char_p, c_char_p]
DLL.add_header.restype = c_int

DLL.set_alpn.argtypes = [c_int, c_char_p]
DLL.set_alpn.restype = c_int

# DLL.set_fingerprint.argtypes = [c_int, c_char_p]
# DLL.set_fingerprint.restype = c_int

# DLL.set_ja3.argtypes = [c_int, c_char_p]
# DLL.set_ja3.restype = c_int

DLL.set_proxy.argtypes = [c_int, c_char_p]
DLL.set_proxy.restype = c_int

DLL.set_url.argtypes = [c_int, c_char_p]
DLL.set_url.restype = c_int

DLL.set_data.argtypes = [c_int, c_char_p]
DLL.set_data.restype = c_int

DLL.set_json.argtypes = [c_int, c_char_p]
DLL.set_json.restype = c_int

DLL.set_bytes.argtypes = [c_int, c_char_p, c_uint32]
DLL.set_bytes.restype = c_int

DLL.set_content_type.argtypes = [c_int, c_char_p]
DLL.set_content_type.restype = c_int

DLL.set_cookie.argtypes = [c_int, c_char_p]
DLL.set_cookie.restype = c_int

DLL.add_cookie.argtypes = [c_int, c_char_p, c_char_p]
DLL.add_cookie.restype = c_int

DLL.set_timeout.argtypes = [c_int, c_char_p]
DLL.set_timeout.restype = c_int

DLL.add_param.argtypes = [c_int, c_char_p]
DLL.add_param.restype = c_int

DLL.get.argtypes = [c_int]
DLL.get.restype = c_void_p

DLL.post.argtypes = [c_int]
DLL.post.restype = c_void_p

DLL.options.argtypes = [c_int]
DLL.options.restype = c_void_p

DLL.put.argtypes = [c_int]
DLL.put.restype = c_void_p

DLL.head.argtypes = [c_int]
DLL.head.restype = c_void_p

DLL.trach.argtypes = [c_int]
DLL.trach.restype = c_void_p

DLL.destroy.argtypes = [c_int]

DLL.free_pointer.argtypes = [c_void_p]

CALLBACK = CFUNCTYPE(None, POINTER(c_char), c_uint32)
DLL.register.argtypes = [c_int, CALLBACK]
DLL.register.restype = c_int
