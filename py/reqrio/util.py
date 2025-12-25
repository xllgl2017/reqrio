import os
from ctypes import CDLL, cdll


def _load_dll() -> CDLL:
    base = os.path.dirname(__file__)
    dll_path = os.path.join(base, 'reqrio.dll')
    os.add_dll_directory(base)
    return cdll.LoadLibrary(dll_path)
