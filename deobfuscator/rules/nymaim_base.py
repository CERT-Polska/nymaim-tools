from deobfuscator.commons import AsmPattern, ror
import struct


class Decryptor:
    def __init__(self):
        self.image_base = None
        self.key = None
        self.xstep = None
        self.off = None
        self.hash_xor = None

    def parse_decryptor(self, raw):
        decryptor_pattern = AsmPattern('\x8F\x45\xE8\x89\x4D\xE4', {
            'main': [
                'pop dword ptr [ebp-0x18]',
                'mov dword ptr [ebp-0x1c], ecx',
                'call @get_key',
                'mov ebx, eax',
                'call @get_step',
                'mov edx, eax',
                'mov dword ptr [ebp-4], eax',
                'mov ecx, dword ptr [ebp-0x1c]',
                'mov eax, $offset',
                'sub ecx, eax',
            ],
            'get_key': [
                'mov eax, $key',
                'ret',
            ],
            'get_step': [
                'mov eax, $step',
                'ret'
            ]
        })
        decryptor = next(decryptor_pattern.matchall(raw))

        self.key = decryptor['$key']
        self.xstep = decryptor['$step']
        self.off = decryptor['$offset']

    def parse_helper(self, raw):
        helper_pattern = AsmPattern('\x8B\x45\xD8\x3D', {
            'main': [
                'mov eax, dword ptr [ebp-0x28]',
                'cmp eax, $ntdll',
                'je $junk2',
                'cmp eax, $kernel32',
                'je $junk2',
                'cmp eax, $junk3',
                'je $junk4'
            ]
        })
        helper = next(helper_pattern.matchall(raw))

        ntdll_h = 0xab30a50a
        x1 = helper['$ntdll'] ^ ntdll_h

        kernl_h = 0x4b1ffe8e
        x2 = helper['$kernel32'] ^ kernl_h

        if x1 != x2:
            raise RuntimeError('failed to get api key')
        self.hash_xor = x1

    def parse_image_base(self, raw):
        image_base_pattern = AsmPattern('\xE8....', {
            'main': [
                'call @get_image_base',
            ],
            'get_image_base': [
                'mov eax, $image_base',
                'ret'
            ]
        })

        for ctx in image_base_pattern.matchall(raw):
            if isinstance(ctx['$image_base'], int) and ctx['$image_base'] % 0x1000 == 0:
                self.image_base = ctx['$image_base']
                break
        else:
            print "[!] No image base found. Trying alternative method..."
            self.alt_parse_image_base(raw)

    def alt_parse_image_base(self, raw):
        image_base_pattern = AsmPattern('\x31\xDB\xE8....\x89\xC6', {
            'main': [
                'xor ebx, ebx',
                'call @get_image_base',
                'mov esi, eax',
            ],
            'get_image_base': [
                'mov eax, $image_base',
                'ret'
            ]
        })

        for ctx in image_base_pattern.matchall(raw):
            if isinstance(ctx['$image_base'], int):
                self.image_base = ctx['$image_base']
                break
        else:
            print "[!] No image base found. Decryption will fail"
            exit()

    def preprocess(self, raw):
        self.parse_decryptor(raw)
        self.parse_helper(raw)
        self.parse_image_base(raw)

    def manual_init(self, key, xstep, off, hash_xor, image_base):
        self.key = key
        self.xstep = xstep
        self.off = off
        self.hash_xor = hash_xor
        self.image_base = image_base

    def nymaim_decrypt(self, raw, from_raw, length):
        from_va = from_raw + self.image_base
        xsize = from_va - self.off
        cur_key = self.key
        if xsize < 0:
            raise RuntimeError("raw too small - min is " + hex(self.off - self.image_base))
        for _ in range(xsize / 4):
            cur_key = (cur_key + self.xstep) & 0xffffffff

        r = ''
        length = min(length, len(raw) - from_raw)
        for i in range(length):
            r += chr(raw[from_raw + i] ^ (ror(cur_key, (xsize & 3) * 8) & 0xff))
            xsize += 1
            if xsize % 4 == 0:
                cur_key = (cur_key + self.xstep) & 0xffffffff
        return r


def decrypt_raw(nymaim, data_raw, length):
    d = Decryptor()
    d.preprocess(nymaim)

    if data_raw + length >= len(nymaim):
        length = len(nymaim) - data_raw

    res = d.nymaim_decrypt(nymaim, data_raw, length)

    patch = True
    if patch:
        nymaim[data_raw:data_raw + length] = res

    return nymaim


def decrypt_routine(nymaim, len_rva, data_rva):
    d = Decryptor()
    d.preprocess(nymaim)

    length = d.nymaim_decrypt(nymaim, len_rva - d.image_base, 4)
    length = struct.unpack('<I', length)[0]
    data = d.nymaim_decrypt(nymaim, data_rva - d.image_base, length)
    return data


def decrypt_raw_all(nymaim):
    d = Decryptor()
    d.preprocess(nymaim)
    raw = d.off - d.image_base
    return decrypt_raw(nymaim, raw, len(nymaim) - raw)
