import struct


def to_uint32(num):
    return struct.pack('<I', num)


def uint32(num):
    return num & 0xFFFFFFFF


def from_uint32(num):
    return struct.unpack('<I', num)[0]


def ror32(n, bits):
    return ((n & 0xFFFFFFFF) >> bits) | ((n << (32-bits)) & 0xFFFFFFFF)


def rol32(n, bits):
    return ((n << bits) & 0xFFFFFFFF) | ((n >> (32-bits)) & 0xFFFFFFFF)


def bswap32(n):
    return (((n & 0x000000FF) << 24) |
            ((n & 0x0000FF00) << 8) |
            ((n & 0x00FF0000) >> 8) |
            ((n & 0xFF000000) >> 24))


def chunks(data, n):
    return [data[i*n:(i+1)*n] for i in range(len(data)/n)]
