import sys

from deobfuscator.rules.nymaim_base import decrypt_raw, decrypt_routine


def usage():
    print 'decryptor raw [nymaim] [data_raw] [length]'
    print 'decryptor routine [nymaim] [len_rva] [data_rva]'
    exit()


def main():
    if len(sys.argv) != 5:
        usage()
    if sys.argv[1] == 'raw':
        nymaim = bytearray(open(sys.argv[2], 'rb').read())
        data_raw = int(sys.argv[3], 16)
        length = int(sys.argv[4], 16)
        decrypt_raw(nymaim, data_raw, length)
    elif sys.argv[1] == 'routine':
        nymaim = bytearray(open(sys.argv[2], 'rb').read())
        len_rva = int(sys.argv[3], 16)
        data_rva = int(sys.argv[4], 16)
        decrypt_routine(nymaim, len_rva, data_rva)
    else:
        usage()

if __name__ == '__main__':
    main()