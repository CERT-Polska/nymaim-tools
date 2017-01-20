import re,struct

get_strings = lambda d: re.findall('[ -~]{3,}',d)


def rol(x, n, b=32):
    n = (b-1) & n
    return x << n | 2 ** n - 1 & x >> b - n


def chunks(data, n):
    return [data[i*n:(i+1)*n] for i in range(len(data)/n)]


def ror(n, bits,b=32):
    m = (2 << b-1) -1
    return ((n & b) >> bits) | ((n << (b-bits)) & b)


def uint32(i):
    return struct.unpack('<I', i)[0]

def append_http(x):
    return ('' if x.startswith('http') else 'http://' ) + x
