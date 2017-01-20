import operator
import struct
from deobfuscator.commons import AsmPattern, MalwareHashDb
from nymaim_base import Decryptor


def ror(n, bits):
    return ((n & 0xFFFFFFFF) >> bits) | ((n << (32-bits)) & 0xFFFFFFFF)


class PatternRule(object):
    def __init__(self, regex, rules):
        self.pattern = AsmPattern(regex, rules)

    def matchall(self, raw):
        return self.pattern.matchall(raw)

    def execute(self, raw, ctx):
        replacement = self.get_replacement(raw, ctx)
        main_size = ctx['main_size']
        addr = ctx['@main']
        nops = '\x90' * (main_size - len(replacement))
        raw[addr:addr+main_size] = nops + replacement
        return True

    def get_rebuild_info(self):
        return {}

    def get_replacement(self, raw, ctx):
        raise RuntimeError('do not call me directly')

    def preprocess(self, raw):
        pass

    def postprocess(self, raw, path=None):
        return raw


class NymaimBaseRule(PatternRule):
    def __init__(self, regex, rules):
        super(NymaimBaseRule, self).__init__(regex, rules)
        # self.pattern.follow_calls = True

    @staticmethod
    def operator_helper(instruction, ctx, raw):
        # if instruction.op_str.replace(' ', '') == 'eax, dword ptr [ebp+8]'.replace(' ', ''):
        if instruction.mnemonic in ['add', 'xor', 'sub']:
            ctx['operator'] = instruction.mnemonic
            return True

    def get_ret_data(self, raw, ctx):
        ret_addr = ctx['@main']+10
        ret_data = raw[ret_addr:ret_addr+4]
        return struct.unpack('<I', ret_data)[0]

    operators = {
        'add': operator.add,
        'sub': operator.sub,
        'xor': operator.xor
    }


class PushPushCallRule1(NymaimBaseRule):
    def __init__(self):
        super(PushPushCallRule1, self).__init__(self.fastmatch, self.rules)

    fastmatch = '[\x50-\x57]\x68....\x68....\xE8'

    rules = {
        'main': [
            'push $whatever',
            'push $param1',
            'push $param2',
            'call @dispatch',
        ],
        'dispatch': [
            'push ebp',
            'mov ebp, esp',
            'push eax',
            'mov eax, dword ptr [ebp+4]',
            'mov dword ptr [ebp+0x10], eax',
            'mov eax, dword ptr [ebp+0xc]',
            NymaimBaseRule.operator_helper,
            'add dword ptr [ebp+4], eax',
            'pop eax',
            'leave',
            'ret 8'
        ]
    }

    def get_replacement(self, raw, ctx):
        operation = self.operators[ctx['operator']]
        real_addr = operation(ctx['$param1'], ctx['$param2']) % (2**32)
        return '\xE8' + struct.pack('<I', real_addr)


class PushPushCallRule2(PatternRule):
    def __init__(self):
        super(PushPushCallRule2, self).__init__(self.fastmatch, self.rules)

    fastmatch = '\x68....\x68....\xE8'

    rules = {
        'main': [
            'push $param1',
            'push $param2',
            'call @dispatch'
        ],
        'dispatch': [
            'push ebp',
            'mov ebp, esp',
            'push eax',
            'push ecx',
            'mov eax, dword ptr [ebp+0xc]',
            'mov ecx, dword ptr [ebp+8]',
            'lea eax, dword ptr [eax+ecx]',
            'mov ecx, dword ptr [ebp+4]',
            'lea eax, dword ptr [eax+ecx]',
            'mov dword ptr [ebp+4], eax',
            'pop ecx',
            'pop eax',
            'leave',
            'ret 8'
        ]
    }

    def get_replacement(self, raw, ctx):
        real_addr = (ctx['$param1'] + ctx['$param2']) % (2**32)
        return '\xE9' + struct.pack('<I', real_addr)


class PushPushCallRule3(NymaimBaseRule):
    def __init__(self):
        super(PushPushCallRule3, self).__init__(self.fastmatch, self.rules)

    fastmatch = '\x68....\x68....\xE8'

    rules = {
        'main': [
            'push $param1',
            'push $param2',
            'call @dispatch'
        ],
        'dispatch': [
            'push ebp',
            'mov ebp, esp',
            'push eax',
            'mov eax, dword ptr [ebp+0xc]',
            NymaimBaseRule.operator_helper,
            'add dword ptr [ebp+4], eax',
            'pop eax',
            'leave',
            'ret 8'
        ]
    }

    def get_replacement(self, raw, ctx):
        operation = self.operators[ctx['operator']]
        real_addr = operation(ctx['$param1'], ctx['$param2']) % (2**32)
        return '\xE9' + struct.pack('<I', real_addr)


class PushJumpRule1(NymaimBaseRule):
    def __init__(self):
        super(PushJumpRule1, self).__init__(self.fastmatch, self.rules)

    fastmatch = '\x68....\xE8'

    rules = {
        'main': [
            'push $param1',
            'call @dispatch'
        ],
        'dispatch': [
            'push ebp',
            'mov ebp, esp',
            'push eax',
            'push ecx',
            'mov eax, dword ptr [ebp+8]',
            'mov ecx, dword ptr [ebp+4]',
            'mov ecx, dword ptr [ecx]',
            NymaimBaseRule.operator_helper,
            'add dword ptr [ebp+4], eax',
            'pop ecx',
            'pop eax',
            'leave',
            'ret 4'
        ]
    }

    def get_replacement(self, raw, ctx):
        operation = self.operators[ctx['operator']]
        ret_data = self.get_ret_data(raw, ctx)
        real_addr = operation(ctx['$param1'], ret_data) % (2**32)
        return '\xE9' + struct.pack('<I', real_addr)


class PushJumpRule2(NymaimBaseRule):
    def __init__(self):
        super(PushJumpRule2, self).__init__(self.fastmatch, self.rules)

    fastmatch = '\x68....\xE8'

    rules = {
        'main': [
            'push $param1',
            'call @dispatch'
        ],
        'dispatch': [
            'push ebp',
            'mov ebp, esp',
            'push eax',
            'push ecx',
            'mov ecx, dword ptr [ebp+4]',
            'mov ecx, dword ptr [ecx]',
            'mov eax, dword ptr [ebp+8]',
            'lea eax, dword ptr [eax+ecx]',
            'mov ecx, dword ptr [ebp+4]',
            'lea eax, dword ptr [eax+ecx]',
            'mov dword ptr [ebp+4], eax',
            'pop ecx',
            'pop eax',
            'leave',
            'ret 4'
        ]
    }

    def get_replacement(self, raw, ctx):
        ret_data = self.get_ret_data(raw, ctx)
        real_addr = (ret_data + ctx['$param1']) % (2**32)
        return '\xE9' + struct.pack('<I', real_addr)


class PushRegisterRule(PatternRule):
    def __init__(self):
        super(PushRegisterRule, self).__init__(self.fastmatch, self.rules)

    fastmatch = '\x6A.\xE8'

    rules = {
        'main': [
            'push $regid',
            'call @dispatch'
        ],
        'dispatch': [
            'cmp dword ptr [esp+4], $eax_id',
            'jne @not_eax',
            'mov dword ptr [esp+4], eax',
            'ret'
        ],
        'not_eax': [
            'cmp dword ptr [esp+4], $ecx_id',
            'jne @not_ecx',
            'mov dword ptr [esp+4], ecx',
            'ret'
        ],
        'not_ecx': []
    }

    def get_replacement(self, raw, ctx):
        if ctx['$ecx_id'] - ctx['$eax_id'] == 1:
            opcode = ctx['$regid'] - ctx['$eax_id'] + 0x50
        else:
            raise RuntimeError('registry ids are not consecutive')
        return chr(opcode)


class XorWithConstRule(PatternRule):
    def __init__(self):
        super(XorWithConstRule, self).__init__(self.fastmatch, self.rules)

    fastmatch = '\xB8....\xE8'

    rules = {
        'main': [
            'mov eax, $const1',
            'call @dispatch'
        ],
        'dispatch': [
            'push ebp',
            'mov ebp, esp',
            'push ebx',
            'mov ebx, $const2',
            'xor eax, ebx',
            'pop ebx',
            'leave',
            'ret'
        ]
    }

    def get_replacement(self, raw, ctx):
        val = ctx['$const1'] ^ ctx['$const2']
        return '\xB8' + struct.pack('<I', val)


class ApiCallRuleBase(PatternRule):
    def __init__(self, regex, rules, call_type):
        super(ApiCallRuleBase, self).__init__(regex, rules)
        self.image_base = None

        self.hashes = MalwareHashDb()
        self.found_api = {}
        self.decryptor = Decryptor()
        self.call_type = call_type

    def preprocess(self, raw):
        self.decryptor.preprocess(raw)

    def nymaim_decrypt(self, raw, api_off):
        r = self.decryptor.nymaim_decrypt(raw, api_off, 4)
        r = struct.unpack('<I', r)[0]
        return r ^ self.decryptor.hash_xor

    def get_rebuild_info(self):
        return {
            'code_rva': 0x1000,
            'image_base': self.decryptor.image_base - 0x1000,
            'iat': self.found_api,
        }

    def execute(self, raw, ctx):
        func_offset = ctx['$func_offset']
        dll_offset = ctx['$dll_offset']
        if not isinstance(func_offset, int) or not isinstance(dll_offset, int):
            return

        api_hash = self.nymaim_decrypt(raw, func_offset)
        func_data = self.hashes.get(api_hash)

        if func_data is None:
            func_data = 'unknown', str(api_hash)

        entry = self.call_type, ctx["@main"], ctx['main_size']
        if entry not in self.found_api:
            self.found_api[entry] = func_data
            return True


class ApiCallRule1(ApiCallRuleBase):
    def __init__(self):
        super(ApiCallRule1, self).__init__(self.regex, self.rules, 'jump')
        self.image_base = None

    rules = {
        'main': [
            'push $func_offset',
            'call @dispatch',
        ],
        'dispatch': [
            'push $dll_offset',
            'call @dispatch2',
        ],
        'dispatch2': [
            'xor eax, eax',
            'jmp @api_dispatcher',
        ],
        'api_dispatcher': [
            'push ebp'
        ]
    }

    regex = '\x68....\xE8....'


class ApiCallRule2(ApiCallRuleBase):
    def __init__(self):
        super(ApiCallRule2, self).__init__(self.regex, self.rules, 'call')
        self.image_base = None

    rules = {
        'main': [
            'push $junk',
            'push $func_offset',
            'push $dll_offset',
            'call @dispatch2',
        ],
        'dispatch2': [
            'push ebp',
            'mov ebp, esp',
            'sub esp, $junk2',
            'push edi',
            'push ebx',
            'push esi',
        ]
    }

    regex = '\x6A.\x68....\x68....'


class ApiCallRule3(ApiCallRuleBase):
    def __init__(self):
        super(ApiCallRule3, self).__init__(self.regex, self.rules, 'jump')
        self.image_base = None

    rules = {
        'main': [
            'push $func_offset',
            'call @dispatch',
        ],
        'dispatch': [
            'push $dll_offset',
            'call @api_dispatcher',
        ],
        'api_dispatcher': [
            'push ebp'
        ]
    }

    regex = '\x68....\xE8....'


all_rules = [
    PushPushCallRule1(),
    PushPushCallRule2(),
    PushPushCallRule3(),
    PushJumpRule1(),
    PushJumpRule2(),
    PushRegisterRule(),
    XorWithConstRule(),
    ApiCallRule1(),
    ApiCallRule2(),
    ApiCallRule3(),
]
