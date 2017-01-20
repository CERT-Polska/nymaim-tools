# coding=utf-8

import re
import binascii
import crypto
import datetime
import string
import hashlib
import zlib
from random import randint
from Crypto.PublicKey import RSA
from printer import *
from bits import *


def rc4_sched_key(password):
    key = range(256)
    j = 0
    for i in range(256):
        j = (j + key[i] + password[i % len(password)]) & 0xFF
        key[i], key[j] = key[j], key[i]
    return key


def rc4_encrypt(key, data):
    i, j = 0, 0
    for ndx in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + key[i]) & 0xFF
        key[j], key[i] = key[i], key[j]
        data[ndx] ^= key[(key[i] + key[j]) & 0xFF]
    return data


def parse_ffd5e56e(raw):
    chunks = [raw[i*4:(i+1)*4] for i in range(len(raw) / 4)]
    pprint('exe_id:                         ', from_uint32(chunks[0]))
    pprint('exe_version:                    ', from_uint32(chunks[1]))
    pprint('const_from_memory1:             ', hex(from_uint32(chunks[2])))
    pprint('const_from_memory2:             ', hex(from_uint32(chunks[3])))
    pprint('hash_of_machine_guid:           ', hex(from_uint32(chunks[4])))
    pprint('hash_of_computer_name:          ', hex(from_uint32(chunks[5])))
    pprint('cpuid xor (eax^edx^ecx):        ', hex(from_uint32(chunks[6])))
    pprint('hash_of_user_name:              ', hex(from_uint32(chunks[7])))
    pprint('hash_of_default_user_name:      ', hex(from_uint32(chunks[8])))
    pprint('SystemProcessAndThreadsInfo:    ', hex(from_uint32(chunks[9])))
    pprint('crc_of_rsa_key:                 ', hex(from_uint32(chunks[10])))
    pprint('ProcessId (TEB[32]):            ', from_uint32(chunks[11]))


def parse_f77006f9(raw):
    chunks = [raw[i*4:(i+1)*4] for i in range(len(raw) / 4)]

    pprint('volume seral number:            ', hex(from_uint32(chunks[0])))
    pprint('crc32(computer name):           ', hex(from_uint32(chunks[1])))
    pprint('crc32(volume name name):        ', hex(from_uint32(chunks[2])))


def parse_014e2be0(raw):
    chunks = [raw[i*4:(i+1)*4] for i in range(len(raw) / 4)]

    pprint('OS Build Number:                ', hex(from_uint32(chunks[0])))
    pprint('OS Major Version:               ', hex(from_uint32(chunks[1])))
    pprint('OS Minor Version:               ', hex(from_uint32(chunks[2])))
    pprint('Is64BitProcess * 32 + 32:       ', hex(from_uint32(chunks[3])))
    pprint('bitmask_of_running_processes:   ', hex(from_uint32(chunks[4])))
    pprint('ProcSidSubauthority[0]:         ', hex(from_uint32(chunks[5])))
    pprint('Is Admin:                       ', hex(from_uint32(chunks[6])))
    pprint('SystemTimeAsFileTime/10^7:      ', from_uint32(chunks[7]))
    pprint('SystemTimeOfDayInformation/10^7:', from_uint32(chunks[8]))
    pprint('SystemDefaultUILanguage ID:     ', from_uint32(chunks[9]))
    pprint('GetSystemDefaultLCID:           ', from_uint32(chunks[10]))
    pprint('zero:                           ', from_uint32(chunks[11]))


def parse_22451ed7(raw):
    chunks = [raw[i*4:(i+1)*4] for i in range(len(raw) / 4)]

    pprint('crc32 from be8ec514:            ', hex(from_uint32(chunks[0])))
    pprint('crc32 from 0282aa05:            ', hex(from_uint32(chunks[1])))


def uri_list(hash, raw):
    ips = raw.split(';')

    for ip in ips:
        pprint('uri found:                        '.format(hash), ip)


def parse_b873dfe0(raw, ctx):
    assert len(raw) == 4
    ctx['has_flag'] = True
    pprint('Flag:  ', from_uint32(raw))


def save_binary(raw, ctx, ftype='exe'):
    fname = ftype + '_' + hashlib.md5(raw).hexdigest() + '.dissected'
    pprint('dumping binary file as', fname)
    with open(fname, 'wb') as f:
        f.write(raw)
    if 'files' not in ctx:
        ctx['files'] = {}
    ctx['files'][fname] = raw


def decrypt_common(raw, rsa_key):
    encrypted_header = raw[-0x40:]
    encrypted_data = raw[:-0x40]

    rsa_e = long(rsa_key['e'])
    rsa_d = long(rsa_key['d'])

    key = RSA.construct((rsa_d, rsa_e))
    pub = key.publickey()
    padded_data = pub.encrypt(encrypted_header, 0)[0]

    # unpadding done wrong
    decrypted_data = padded_data[padded_data.find('\xff\x00') + 2:]

    md5 = decrypted_data[0:16]
    blob = decrypted_data[16:32]
    length = from_uint32(decrypted_data[32:36])

    serpent_decrypted = crypto.s_decrypt(encrypted_data, blob)[:length]

    pprint('decrypted data, hash verification:', md5.encode('hex'), hashlib.md5(serpent_decrypted).hexdigest())
    assert md5.encode('hex') == hashlib.md5(serpent_decrypted).hexdigest()

    return serpent_decrypted


def raw_binary_decrypt(raw, ctx, rsa_key, idname):
    serpent_decrypted = decrypt_common(raw, rsa_key)

    pprint('decrypted data, magic verification:', idname, serpent_decrypted[:4], 'ARCH')
    assert serpent_decrypted[:4] == 'ARCH'

    aplib_unpacked = crypto.aplib_unpack(serpent_decrypted[16:])

    pprint('blob decrypted, sample data:', aplib_unpacked.encode('hex')[:60])
    pprint('decryption successful, saving data to file')
    save_binary(aplib_unpacked, ctx, 'exe')
    if idname is not None:
        if 'dropped_files' not in ctx:
            ctx['dropped_files'] = {}
        ctx['dropped_files'][idname] = raw


def nymaim_decrypt_data_2(raw, key0, key1):
    """
    decrypt final config (only raw data, keys passed as parameters)
    """
    prev_chr = 0
    result = ''
    for i, c in enumerate(raw):
        bl = ((key0 & 0x000000FF) + prev_chr) & 0xFF
        key0 = (key0 & 0xFFFFFF00) + bl
        prev_chr = ord(c) ^ bl
        result += chr(prev_chr)
        key0 = (key0 + key1) & 0xFFFFFFFF
        key0 = ((key0 & 0x00FFFFFF) << 8) + ((key0 & 0xFF000000) >> 24)
    return result


def nested_config_decrypt(raw, ctx, rsa_key):
    data = decrypt_common(raw, rsa_key)

    key0 = from_uint32(data[0:4])
    key1 = from_uint32(data[4:8])
    length = from_uint32(data[8:12])

    unpacked_config = nymaim_decrypt_data_2(data[12:], key0, key1)

    pprint('validating decryption...')
    pprint('checking', len(unpacked_config), '==', length)
    assert len(unpacked_config) == length

    pprint('unpacked nested config')
    indent()

    nymaim_blob_parse(unpacked_config, ctx, rsa_key)

    undent()


def parse_0c526e8b(raw, ctx, rsa_key):
    unknown_header = raw[:8]
    pprint('some header:                    ', unknown_header.encode('hex'))

    key0 = from_uint32(raw[8:12])
    key1 = from_uint32(raw[12:16])
    length = from_uint32(raw[16:20])
    pprint('encrypted data length:          ', length)

    unpacked_config = nymaim_decrypt_data_2(raw[20:], key0, key1)

    pprint('decrypted data, magic verification:', unpacked_config[:4], 'ARCH')
    assert unpacked_config[:4] == 'ARCH'

    aplib_unpacked = crypto.aplib_unpack(unpacked_config[16:])

    pprint('yet another nested chunk... Seriously, wtf nymaim?')
    indent()

    nymaim_blob_parse(aplib_unpacked, ctx, rsa_key)

    undent()


def parse_875c2fbf(raw, ctx):
    pprint('unencrypted binary')
    pprint('some pointless header:          ', raw[:4].encode('hex'))

    real_binary = raw[4:]
    save_binary(real_binary, ctx)


def parse_f325ea0b(raw):
    pprint('Keylogging/session stealing')
    save_binary(raw, 'keylog')


def parse_08750ec5(raw, ctx, rsa_key):
    data = decrypt_common(raw, rsa_key)

    key0 = from_uint32(data[0:4])
    key1 = from_uint32(data[4:8])
    length = from_uint32(data[8:12])

    decrypted = nymaim_decrypt_data_2(data[12:], key0, key1)

    assert len(decrypted) == length

    aplib_unpacked = crypto.aplib_unpack(decrypted[16:])

    pprint('and another nested chunk...')
    indent()

    nymaim_blob_parse(aplib_unpacked, ctx, rsa_key)

    undent()


def parse_1f5e1840(raw, ctx, rsa_key):
    data = decrypt_common(raw, rsa_key)

    length = data[:4]
    length = from_uint32(length)

    aplib_unpacked = crypto.aplib_unpack(data[4:], length)
    save_binary(aplib_unpacked, ctx, 'injects')

    save_binary(aplib_unpacked, 'injects')


def dump_excludes(raw, ctx):
    pprint('...and excludes (or something) in plain sight, dumping')
    save_binary(raw, ctx, 'excludes')


def parse_76fbf55a(raw):
    if all(c == '\x00' for c in raw):
        pprint('76fbf55a chunk is null, with length', len(raw))
    else:
        pprint('b68encoded string:              ', raw)


def parse_d2bf6f4a(raw, ctx):
    pprint('parsing state information')
    ctx['d2bf6f4a'] = raw
    indent()
    for i in range(36/4):
        # data field 3 - injects
        # data field 6 - excludes
        pprint('data field {}:               '.format(i), hex(from_uint32(raw[i*4:(i+1)*4])))
    undent()

    body = raw[36:]
    pprint('body:                           ', body)


def parse_3e5a221c(raw):
    chunks = from_uint32(raw[:4])
    pprint('chunk count:', chunks)
    indent()
    for i in range(chunks):
        s = 4 + i * 16
        binid = raw[s:s + 4].encode('hex')
        binver = raw[s + 4:s + 8].encode('hex')
        timestamp = datetime.datetime.fromtimestamp(from_uint32(raw[s + 8:s + 12]))
        zero = from_uint32(raw[s + 12:s + 16])
        pprint('chunk: [binary id: {}] [version: {}] [timestamp: {}] [zero: {}]'.format(binid, binver, timestamp, zero))

    undent()


def parse_cae9ea25(raw, ctx, rsa_key):
    nested_config_decrypt(raw, ctx, rsa_key)


def parse_0282aa05(raw, ctx, rsa_key):
    nested_config_decrypt(raw, ctx, rsa_key)
    ctx['0282aa05'] = raw


def parse_be8ec514(raw, ctx):
    uri_list('be8ec514', raw)
    ctx['be8ec514'] = raw
    if 'uris' not in ctx:
        ctx['uris'] = []
    ctx['uris'] += raw.split(';')


def parse_138bee04(raw):
    uri_list('138bee04', raw)


def parse_8de8f7e6(raw):
    day, mth, year = [from_uint32(raw[i*4:(i+1)*4]) for i in range(len(raw) / 4)]
    pprint('time restriction for binary...', '{:04}-{:02}-{:02}'.format(year, mth, day))


def parse_b84216c7(raw):
    ip = '.'.join(str(ord(c)) for c in raw)
    pprint('client ip', ip)


def parse_cb0e30c4(raw):
    pprint('number of seconds client should sleep:', from_uint32(raw))


def parse_f31cc18f(raw):
    dwords = [from_uint32(i) for i in chunks(raw, 4)]
    pprint('[raw]:           ', raw.encode('hex'))
    pprint('zero 1:          ', dwords[0])
    pprint('zero 2:          ', dwords[1])
    pprint('crc of sth [68F7B9CE]: ', hex(dwords[2]))
    pprint('crc of sth [E4F1DA1D]: ', hex(dwords[3]))
    pprint('crc of sth [778DB436]: ', hex(dwords[4]))
    pprint('crc of sth [778D7466]: ', hex(dwords[5]))
    pprint('waitForSingleObject problem (no timeout):', dwords[6])


def parse_c5e73bd8(raw):
    c = chunks(raw, 4)
    pprint('seconds to wait for SYN_HANDLE_1', c[0])
    pprint('unk, something                ', c[1])
    pprint('seconds to halt execution     ', c[2])


def parse_c5075849(raw):
    data = chunks(raw, 4)
    pprint('a5: [some command type]    ', from_uint32(data[0]))
    pprint('a4[4]: [crc32 of 4ad102e5] ', hex(from_uint32(data[1])))
    pprint('a7:    [crc32 of 138bee04] ', hex(from_uint32(data[2])))
    pprint('a4[20]: [ticks?]           ', hex(from_uint32(data[3])))
    pprint('a4[2]:                     ', from_uint32(data[4]))
    pprint('gettckcnt() - a4[20]:      ', from_uint32(data[5]))
    pprint('a4[19]:                    ', from_uint32(data[6]))
    pprint('a4[21] - a4[20]:           ', from_uint32(data[7]))
    pprint('a4[22] - a4[20]:           ', from_uint32(data[8]))
    pprint('a4[23] - a4[20]:           ', from_uint32(data[9]))
    pprint('a4[24]:                    ', from_uint32(data[10]))
    pprint('a4[25]:                    ', from_uint32(data[11]))
    pprint('a4[26]:                    ', from_uint32(data[12]))
    pprint('a4[27]:                    ', from_uint32(data[13]))
    pprint('a4[29]: [tcp_port]         ', from_uint32(data[14]))
    pprint('a4[28]: [client_ip]        ', hex(from_uint32(data[15])))
    pprint('a4[35]:                    ', from_uint32(data[16]))
    pprint('a4[36]:                    ', from_uint32(data[17]))
    pprint('a4[37]:                    ', from_uint32(data[18]))
    pprint('a4[38]:                    ', from_uint32(data[19]))
    pprint('a4[41]__a4[40] >> 10:      ', from_uint32(data[20]))
    pprint('a4[43]__a4[42] >> 10:      ', from_uint32(data[21]))
    pprint('a4[45]__a4[44] >> 10:      ', from_uint32(data[22]))
    pprint('a4[47]__a4[46] >> 10:      ', from_uint32(data[23]))
    pprint('memcpy 1:                  ', ''.join(data[24:24 + 168 / 2]).encode('hex'))
    pprint('memcpy 2:                  ', ''.join(data[152:156]).encode('hex'))
    pprint('procid:                    ', from_uint32(data[156]))


def parse_920f2f0c(raw, ctx, rsa_key):
    data = decrypt_common(raw, rsa_key)
    length = data[:4]
    length = from_uint32(length)
    aplib_unpacked = crypto.aplib_unpack(data[4:], length)
    save_binary(aplib_unpacked, ctx, 'injects')


def parse_930f2f0c(raw, ctx, rsa_key):
    data = decrypt_common(raw, rsa_key)
    length = data[:4]
    length = from_uint32(length)
    aplib_unpacked = crypto.aplib_unpack(data[4:], length)
    save_binary(aplib_unpacked, ctx, 'injects')


def nymaim_blob_parse(blob, ctx, rsa_key):
    """
    decrypt and interpret config (uses hardcoded hashes)
    """
    i = 0
    known_hashes = {
     '748e2a6c', 'ffd5e56e', '014e2be0', 'f77006f9',
     '22451ed7', 'b873dfe0', '0c526e8b', '875c2fbf',
     '08750ec5', '1f5e1840', '76daea91', 'be8ec514',
     '138bee04', '1a701ad9', '30f01ee5', '3bbc6128',
     '39bc61ae', '261dc56c', 'a01fc56c', 'cae9ea25',
     '41f2e735', '1ec0a948', '18c0a95e', '3d717c2e',
     '76fbf55a', '3e5a221c', 'b84216c7', 'd2bf6f4a',
     'cb0e30c4', '5babb165', '0282aa05', 'f31cc18f'}
    while i < len(blob):
        hash = blob[i:i + 4].encode('hex')
        rawlen = from_uint32(blob[i + 4:i + 8])
        raw = blob[i + 8:i + 8 + rawlen]
        try:
            pprint()
            sym = '[+]' if hash in known_hashes else '[_]'
            res = '<<<' if ctx['is_response'] else '>>>'
            pretty = ''.join(c if 0x20 <= ord(c) < 0x7f else '.' for c in raw[:20])
            snip = raw[:20].encode('hex') + ('...' if len(raw) > 20 else '   ')
            crc = hex(zlib.crc32(raw) % 2**32)[2:]
            pprint("<{}> {} {} [{:6} bytes]: {:43} {:20} {}".format(hash, res, sym, len(raw), snip, pretty, crc))

            indent()
            if hash == '748e2a6c':
                pprint(raw.decode('utf-16'))
            if hash == 'ffd5e56e':  # fingerprint 1
                parse_ffd5e56e(raw)
            elif hash == '014e2be0':  # fingerprint 2 + timestamp
                parse_014e2be0(raw)
            elif hash == 'f77006f9':  # fingerprint 3
                parse_f77006f9(raw)
            elif hash == '22451ed7':  # crc's
                parse_22451ed7(raw)
            elif hash == 'b873dfe0':  # some flag
                parse_b873dfe0(raw, ctx)
            elif hash == '0c526e8b':  # nested chunk (probably always binary)
                parse_0c526e8b(raw, ctx, rsa_key)
            elif hash == '875c2fbf':  # unencrypted binary
                parse_875c2fbf(raw, ctx)
            elif hash == '08750ec5':  # nested blob
                parse_08750ec5(raw, ctx, rsa_key)
            elif hash == '1f5e1840':  # injects
                parse_1f5e1840(raw, ctx, rsa_key)
            elif hash == '76daea91':  # end of data marker
                pprint('"handshake init" chunk for dropper (used at the beginning)')
            elif hash == 'be8ec514':  # uri list
                parse_be8ec514(raw, ctx)
            elif hash == '138bee04':  # secondary uri list
                parse_138bee04(raw)
            elif hash in ['1a701ad9', '30f01ee5', '3bbc6128', '39bc61ae', '261dc56c', 'a01fc56c']:
                raw_binary_decrypt(raw, ctx, rsa_key, hash)
            elif hash == '76fbf55a':  # padding
                parse_76fbf55a(raw)
            elif hash == 'cae9ea25':  # nested config
                parse_cae9ea25(raw, ctx, rsa_key)
            elif hash == '0282aa05':  # primary nested config
                parse_0282aa05(raw, ctx, rsa_key)
            elif hash == 'd2bf6f4a':  # state
                parse_d2bf6f4a(raw, ctx)
            elif hash in ['41f2e735', '1ec0a948', '18c0a95e', '3d717c2e']:
                dump_excludes(raw, ctx)
            elif hash == '8de8f7e6':
                parse_8de8f7e6(raw)
            elif hash == '3e5a221c':  # chunk information
                parse_3e5a221c(raw)
            elif hash == '5babb165':  # "hello" chunk
                pprint('"handshake init" chunk for payload (used at the beggining)')
            elif hash == 'b84216c7':  # client ip
                parse_b84216c7(raw)
            elif hash == 'cb0e30c4':
                parse_cb0e30c4(raw)
            elif hash == 'c5075849':
                parse_c5075849(raw)
            elif hash == 'f31cc18f':
                parse_f31cc18f(raw)
            elif hash == 'f325ea0b':
                parse_f325ea0b(raw)
            elif hash == 'c5e73bd8':
                parse_c5e73bd8(raw)
            elif hash == '920f2f0c':
                parse_920f2f0c(raw, ctx, rsa_key)
            elif hash == '930f2f0c':
                    parse_930f2f0c(raw, ctx, rsa_key)
            else:
                pprint('chunk not REed yet (extracting printable strings...)')
                indent()
                for f in re.findall('[\x20-\x7e]{9,}', raw):
                    pprint('string: ', f)

                undent()
                if len(raw) > 20:
                    rowlen = 40
                    for row in range(min(16, (len(raw) + rowlen - 1) / rowlen)):
                        pretty = ''.join(c if 0x20 <= ord(c) < 0x7f else '.' for c in raw[row*rowlen:(row+1)*rowlen])
                        pprint('hexdump...: {:84} {}'.format(raw[row*rowlen:(row+1)*rowlen].encode('hex'), pretty))
            undent()
            if 'chunks' not in ctx:
                ctx['chunks'] = []
            ctx['chunks'].append([hash, raw])
        except Exception as e:
            pprint('error', e)

        i += 8 + rawlen


def nymaim_final_encrypt(key, data):
    n0 = randint(0, 15)
    n1 = randint(0, 15)

    salt = ''.join(chr(randint(0, 255)) for _ in range(n0))
    pad = ''.join(chr(randint(0, 255)) for _ in range(n1))
    payload_len = to_uint32(len(data) + 12)
    rest_of_header = '\x00' * 8
    payload_len_minus_header = to_uint32(len(data))
    header = payload_len + rest_of_header + payload_len_minus_header

    to_be_encrypted = header + data + pad

    key = rc4_sched_key([ord(c) for c in key + salt])
    encrypted = rc4_encrypt(key, [ord(c) for c in to_be_encrypted])

    n0 += randint(0, 15) << 4
    n1 += randint(0, 15) << 4
    return chr(n0) + chr(n1) + salt + ''.join(chr(c) for c in encrypted)


def nymaim_final_decrypt(key, raw_data):
    raw_bytes = list(ord(c) for c in raw_data)

    nibble0 = raw_bytes[0] & 0xF
    nibble1 = raw_bytes[1] & 0xF
    salt = raw_bytes[2:2+nibble0]

    key = list(ord(c) for c in key)
    password = key + salt

    if nibble1:
        data = raw_bytes[2+nibble0:-nibble1]
    else:
        data = raw_bytes[2 + nibble0:]

    if len(data) < 4:
        pprint('FAILED TO DECRYPT (data too short):', raw_data.encode('hex'))
        return

    rc4_key = rc4_sched_key(password)
    x = rc4_encrypt(rc4_key, data)
    decrypted = ''.join(chr(c) for c in x)

    decrypted_len = from_uint32(decrypted[:4])

    if decrypted_len != len(decrypted) - 4:
        pprint('FAILED TO DECRYPT (or not nymaim data):', str(decrypted_len), '!=', str(len(decrypted) - 4))
        pprint('RAW: ', raw_data[:60].encode('hex'), hashlib.md5(raw_data).hexdigest())
        raise RuntimeError("Couldn't decrypt nymaim data " + raw_data[:60].encode('hex') + str(decrypted_len))
    return decrypted[16:]


def parse_raw_response(raw_data, ctx, rsa_key, rc4_key):
    if all((c in string.printable for c in raw_data)):
        raw_data = raw_data[raw_data.find('=') + 1:]
        try:
            raw_data = raw_data.decode('base64')
        except binascii.Error:
            pprint('failed to decode data with base64 - if too much requests fail than something is fucked up')
            pprint('raw data - ', raw_data[:30])

    nymaim_blob = nymaim_final_decrypt(rc4_key, raw_data)

    nymaim_blob_parse(nymaim_blob, ctx, rsa_key)
