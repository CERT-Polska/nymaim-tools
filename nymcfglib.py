import string
from libs.stream import S
from libs.misc import *
import struct
from printer import pprint


class NymCfgStream(S):
    def __iter__(self):
        return self
    
    def next(self):
        try:
            h = self.dword()
        except:
            raise StopIteration
        
        s = self.dword()
        data = self.read(s)
        return h,data

class M(object):
    def __init__(self,dbg=None,base=0,mem=''):
        self.mem = mem
        self.base = base
        self.yhits = set()
        self._workers = {}

    def worker(self,name):
        return self._workers[name]
        
    def regex(self,patt,flags=0,a=0,n=None):
        data = self.read(a,n)
        for g in re.finditer(patt,data,flags=flags):
            yield a+g.start()
        
    def read(self,a,n):
        if self.mem:
            return self.mem[a:(a+n )if n else None]

    def dword(self,a):
        return struct.unpack('I',self.read(a,4))[0]

    def word(self,a):
        return struct.unpack('H',self.read(a,2))[0]

    def byte(self,a):
        return struct.unpack('=B',self.read(a,1))[0]

    def read_addr(self,a):
        return self.dword(a)

class Mem(M):
    def __init__(self,_data,base=None,frommem=False):
        super(Mem,self).__init__()
        self.base = base
        self._data = _data
        self.dsize = len(_data)

    def read(self,a=0,n=None):
        a = (a-self.base )if a >= self.base else a
        return self._data[a:(a+n )if n else None]
        
class NymaimExtractor:

    CFG_DNS = 0x1b69e661
    CFG_TTL = 0xe6f7e88d
    CFG_URL = 0x6b02c248
    CFG_DGA_HASH = 0x2aa0aed9
    CFG_ENC_KEY  = 0x22e60b51
    CFG_DOMAINS  = 0x1d4b5d09
    CFG_RSA_KEY  = 0x2f127ffb
    CTG_32BIT_TMPL_1 = 0x4c1ad0bb
    CTG_32BIT_TMPL_2 = 0x1ae78782
    CTG_64BIT_TMPL = 0xf34a67ff
    CFT_NOTEPAD_TMPL = 0xb2ea894d
    CFG_FAKE_ERROR_MSG = 0xfcce74b6
    CFG_PEER_DOMAINS = 0xf212b5af

    CFG_BINARY_TYPES = {
        1: 'botnet_peer',
        20: 'dropper',
        30: 'payload',
    }

    def __init__(self):
        pass

    def nymaim_decrypt_data_2(self, raw, key0, key1):
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

    def nymaim_extract_blob(self, mem, ndx):
        """
        decrypt final config (read keys and length and decrypt raw data)
        """
        key0 = mem.dword(ndx)
        key1 = mem.dword(ndx+4)
        len = mem.dword(ndx+8)
        return self.nymaim_decrypt_data_2(mem.read(ndx + 12, len), key0, key1)

    def nymaim_parse_blob(self, blob):
        """
        decrypt and interpret config (uses hardcoded hashes)
        """
        parsed = {'domains': [], 'urls': [], 'dns': [], 'type': 'nymaim'}
        for hash, raw in NymCfgStream(blob):
            try:
                pprint("<{}>: {}".format(hash, raw.encode('hex') if len(raw) == 4 else raw))
                if hash == self.CFG_URL:  # '48c2026b':
                    parsed['urls'] += [{'url': append_http(raw[20:].rstrip(';'))}]
                elif hash == self.CFG_DGA_HASH:  # 'd9aea02a':
                    parsed['dga_hash'] = [uint32(h) for h in chunks(raw, 4)]
                elif hash == self.CFG_DOMAINS:  # '095d4b1d':
                    parsed['domains'] += [{'cnc': append_http(raw[4:].rstrip(';'))}]
                elif hash == self.CFG_ENC_KEY:  # '510be622':
                    parsed['encryption_key'] = raw
                elif hash == self.CFG_RSA_KEY:  # 'fb7f122f':
                    bits = uint32(raw[:4])
                    bytes = bits / 8
                    d = raw[4:4+bytes].encode('hex')
                    e = raw[4+bytes:4+bytes+bytes].encode('hex')
                    parsed['public_key'] = {
                        'n': str(int(d, 16)),
                        'e': int(e, 16),
                    }
                elif hash == self.CFG_TTL:  # '8de8f7e6':
                    if len(raw) == 12:
                        year, month, day = uint32(raw[-4:]), uint32(raw[4:-4]), uint32(raw[:4])
                        parsed['time_restriction'] = '{}-{:02}-{:02}'.format(year, month, day)
                    else:
                        parsed['time_restriction'] = [raw.encode('hex')]
                elif hash == self.CFG_DNS:
                    parsed['dns'] += raw.split(';')
                elif hash == self.CTG_32BIT_TMPL_1:
                    parsed['template_32bit_1'] = raw
                elif hash == self.CTG_32BIT_TMPL_2:
                    parsed['template_32bit_2'] = raw
                elif hash == self.CTG_64BIT_TMPL:
                    parsed['template_64bit_2'] = raw
                elif hash == self.CFT_NOTEPAD_TMPL:  # notepad template
                    parsed['notepad_template'] = raw
                elif hash == self.CFG_FAKE_ERROR_MSG:  # fake error message, shown to user on startup
                    parsed['fake_error_message'] = raw
                elif hash == self.CFG_PEER_DOMAINS:
                    parsed['domains'] += [{'cnc': x} for x in raw.split(';') if x]
                elif (all(c in string.printable for c in raw) and len(raw) > 3) or len([c for c in raw if c in string.printable]) > 10:
                    if 'other_strings' not in parsed:
                        parsed['other_strings'] = {}
                    parsed['other_strings'][hex(hash)] = raw.encode('hex')
            except RuntimeError:
                # error during parsing...
                if 'errored_on' not in parsed:
                    parsed['errored_on'] = []
                parsed['errored_on'] += [{'hash': hash, 'raw': raw.encode('hex')}]
        return parsed

    def nymaim_brute_blob(self, mem):
        """
        bruteforce start index of config in decrypted data (decrypted data contains more than config block).
        Lame, but should be stable and fast enough.
        """
        for i in reversed(range(mem.base, mem.base+mem.dsize-12)):
            blob_len = mem.dword(i+8)
            if 100 < blob_len < 8000:
                blob = self.nymaim_extract_blob(mem, i)
                if '8.8.8.8' in blob or 'rundll' in blob or\
                    ('~[' in blob and ']/' in blob and ':53' in blob):
                    return self.nymaim_parse_blob(blob)

def set_prog_version(m, hit, *args):
    mem = m.read(hit, 100)
    type_id_offset = mem.find('C745D0'.decode('hex'))
    binary_id_offset = mem.find('C745D4'.decode('hex'))

    type_id = uint32(mem[type_id_offset + 3:type_id_offset + 7])
    binary_id = uint32(mem[binary_id_offset + 3:binary_id_offset + 7])

    if type_id in NymaimExtractor.CFG_BINARY_TYPES:
        type_name = NymaimExtractor.CFG_BINARY_TYPES[type_id]
    else:
        type_name = str(type_id)

    return {
        'exe_type': type_name,
        'exe_version': binary_id,
    }


def extract_config(raw):
    m = Mem(raw, 0)
    ext = NymaimExtractor()
    return ext.nymaim_brute_blob(m)
