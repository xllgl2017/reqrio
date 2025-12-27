import sys
import os
from ctypes import CDLL, cdll


def _load_dll() -> CDLL:
    base = os.path.dirname(__file__)
    if sys.platform=='win32':
        dll_path = os.path.join(base, 'reqrio.dll')
    elif sys.platform=='linux':
        dll_path = os.path.join(base, 'libreqrio.so')
    else:
        raise Exception('unsupported platform')
    # os.add_dll_directory(base)
    return cdll.LoadLibrary(dll_path)
