import os
import capstone as cs
import re
import rebuild
import pefile
import struct


def ror(n, bits):
    return ((n & 0xFFFFFFFF) >> bits) | ((n << (32-bits)) & 0xFFFFFFFF)


def split_once(data, char=' '):
    ndx = data.find(char)
    if ndx < 0:
        return data, ''
    return data[:ndx], data[ndx + len(char):]


def asset_path(asset):
    return os.path.join(os.path.dirname(__file__), asset)


class DeobfuscationFailed:
    def __init__(self):
        pass


class Deobfuscator(object):
    def __init__(self, rules, path=None):
        self.rules = rules
        self.path = path

    def deobfuscate(self, raw):
        to_remove = []
        for rule in self.rules:
            try:
                rule.preprocess(raw)
            except:
                print '[!] rule', rule.__class__.__name__, 'failed'
                to_remove.append(rule)
        self.rules = [r for r in self.rules if r not in to_remove]

        for i in range(10):
            changes = self.deobfuscation_pass(self.rules, raw)
            print 'PASS {} - TOTAL {} CHANGES'.format(i, changes)
            if not changes:
                print 'done'
                break

        for rule in self.rules:
            try:
                raw = rule.postprocess(raw, path=self.path)
            except:
                print '[!] rule', rule.__class__.__name__, 'failed'

        iat = {}
        image_base = 0
        code_rva = 0
        for rule in self.rules:
            info = rule.get_rebuild_info()
            if 'iat' in info:
                iat.update(info['iat'])
            if 'code_rva' in info:
                code_rva = info['code_rva']
            if 'image_base' in info:
                image_base = info['image_base']
        if image_base and iat and code_rva:
            raw = self.rebuild(raw, iat, image_base, code_rva)

        return raw

    def rebuild(self, raw, iat, image_base, code_rva):
        rebuilder = rebuild.PeRebuilder(raw, code_rva)
        rebuilder.set_image_base(image_base)
        rebuilder.rebuild_iat(iat.values())
        raw = rebuilder.rebuild()

        imports = {}
        pe = pefile.PE(data=raw)
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                imports[entry.dll, imp.name] = imp.address

        for (calltype, addr, chunksize), func in sorted(iat.iteritems()):
            if calltype == 'jump':
                opcode = '\xFF\x25' + struct.pack('<I', imports[func])
                opcode += '\xCC' * (chunksize - len(opcode))
            elif calltype == 'call':
                opcode = '\xFF\x15' + struct.pack('<I', imports[func])
                opcode += '\x90' * (chunksize - len(opcode))
            else:
                raise RuntimeError("Unknown call type: ", calltype)
            pe.set_bytes_at_rva(0x1000 + addr, opcode)

        return pe.write()

    def deobfuscation_pass(self, rules, raw):
        total_changes = 0
        for rule in rules:
            try:
                changes = 0
                for match in rule.matchall(raw):
                    if rule.execute(raw, match):
                        changes += 1
                print '{:20}: {} changes'.format(rule.__class__.__name__, changes)
                total_changes += changes
            except:
                print '[!] rule', rule.__class__.__name__, 'failed'
                import traceback
                traceback.print_exc()
        return total_changes


class MalwareHashDb:
    def __init__(self, filename='assets/hashes.mlwr.csv'):
        hashes = {}
        filename = asset_path(filename)
        with open(filename, 'r') as datafile:
            lines = datafile.readlines()
            for line in lines:
                hash, func, dll = line.rstrip().split(',')
                hash = int(hash)
                if hash in hashes and hashes[hash][1] != func:
                    # print '[-] collision for hashes', hashes[hash], 'and', (dll, func)
                    pass  # silently ignore
                hashes[hash] = (dll, func)
        self.hashes = hashes

    def get(self, hash):
        if hash in self.hashes:
            return self.hashes[hash]


class AsmPattern(object):
    def __init__(self, regex, rules, debug=False):
        self.regex = regex
        self.rules = rules
        self.disasm = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
        self.auto_follow_jumps = True
        self.ignore_nops = True
        self.follow_calls = False
        self.debug = debug

        for rulename, rule in self.rules.iteritems():
            for i, cmd in enumerate(rule):
                if isinstance(cmd, basestring):
                    rule[i] = self.opcode_matcher(cmd)

    def finditer(self, raw):
        pass

    def matchall(self, raw):
        reg = re.compile(self.regex, re.DOTALL)
        for i in reg.finditer(raw):
            ndx = i.start()
            match = self.match(raw, ndx)
            if match:
                yield match

    def match(self, raw, va):
        ctx = {'@main': va}
        try:
            return self.match_rule(self.rules['main'], raw, va, ctx, is_main=True)
        except DeobfuscationFailed:
            pass

    def opcode_to_va(self, opcode):
        try:
            return int(opcode.op_str, base=0)
        except ValueError:
            raise DeobfuscationFailed

    def process_opcode_mismatch(self, raw, ctx, va, rules_left, actual, is_main):
        if actual.mnemonic == 'jmp' and self.auto_follow_jumps:
            new_va = self.opcode_to_va(actual)
            return self.match_rule(rules_left, raw, new_va, ctx, is_main)
        if actual.mnemonic == 'call' and self.follow_calls:
            new_va = self.opcode_to_va(actual)
            return self.match_rule(rules_left, raw, new_va, ctx, is_main)
        if actual.mnemonic == 'nop' and self.ignore_nops:
            return self.match_rule(rules_left, raw, va, ctx, is_main)

    def opcode_matcher(self, expected):
        expected_mnemonic, expected_op = split_once(expected)

        expected_pat = re.escape(expected_op).replace('\\_', '_')
        expected_pat = re.sub('\\\\\\$(\\w+)', '(?P<\\1>.+)', expected_pat)
        expected_reg = re.compile(expected_pat.replace('\\ ', ''))

        def matcher(actual, ctx, raw):
            if self.debug:
                print hex(actual.address), expected, '<->', actual.mnemonic, actual.op_str
            if expected_mnemonic != actual.mnemonic:
                return False

            if expected_op.startswith('@'):
                new_va = self.opcode_to_va(actual)
                new_rule = self.rules[expected_op[1:]]
                ctx['@'+expected_op[1:]] = new_va
                return self.match_rule(new_rule, raw, new_va, ctx)
            else:
                op_str = actual.op_str.replace(' ', '')
                m = expected_reg.match(op_str)
                if not m:
                    return False

                for name, value in m.groupdict().iteritems():
                    try:
                        ctx['$' + name] = int(value, base=0)
                    except ValueError:
                        ctx['$' + name] = value
            return True
        return matcher

    def match_rule(self, rule, raw, va, ctx, is_main=False):
        start_va = va
        for rule_ndx, expected in enumerate(rule):
            if va < 0 or va + 15 >= len(raw):
                return False

            actual = list(self.disasm.disasm(str(raw[va:va + 15]), va, 1))
            if not actual:
                return False
            actual = actual[0]
            va += actual.size

            if isinstance(expected, basestring):
                expected = self.opcode_matcher(expected)

            if not expected(actual, ctx, raw):
                return self.process_opcode_mismatch(raw, ctx, va, rule[rule_ndx:], actual, is_main)
        if is_main:
            ctx['main_size'] = va - start_va
        return ctx

