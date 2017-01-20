import os
from ctypes import c_buffer, cdll

def get_my_path():
    me = os.path.abspath(os.path.expanduser(__file__))
    return os.path.dirname(me)


def load_dll(path):
    p = get_my_path()
    return cdll.LoadLibrary(os.path.join(p,path))


LIB=load_dll('lib/serpent.so')

S_BLOCK_SIZE = 16
align_size = lambda n:(n + (S_BLOCK_SIZE-1)) & (~(S_BLOCK_SIZE-1))


from ctypes import cdll,c_buffer
def aplib_unpack(data,s=0):
    aPLIB=load_dll('lib/aplib.so')
    cin = c_buffer(data)
    cout = c_buffer(s if s else len(data)*50)
    n=aPLIB.aP_depack(cin,cout)
    return cout.raw[:n]


def s_decrypt(data,key):
     clen = align_size(len(data))
     ckey = c_buffer(key)
     cin  = c_buffer(data)
     cout = c_buffer(clen)
     LIB.decrypt(cin,clen,ckey,cout)
     return cout.raw

def s_encrypt(data,key):
     clen = align_size(len(data))
     data = data.ljust(clen,"\x00")
     ckey = c_buffer(key)
     cin  = c_buffer(data)
     cout = c_buffer(clen)
     LIB.encrypt(cin,clen,ckey,cout)
     return cout.raw
