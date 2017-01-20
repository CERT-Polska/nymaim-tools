import os
import pefile as p
import struct

from libs.sections import SectionDoubleP


def uint32(i):
    return struct.pack('<I', i)


def round_up(val, to):
    return (val + to - 1) / to * to


def asset_path(asset):
    return os.path.join(os.path.dirname(__file__), asset)


class ThunkTable:
    def __init__(self, function_names):
        self.function_names = function_names

    def write_names(self):
        return ''.join('\0\0' + name + '\0' for name in self.function_names)

    def write_thunks(self, names_rva):
        result = ""
        rva_offset = 0
        for name in self.function_names:
            result += uint32(names_rva + rva_offset)
            rva_offset += len(name) + 3
        result += '\0' * 4
        return result


class ImageImportDescriptor:
    def __init__(self, name, functions):
        self.name = name
        self.functions = functions
        self.thunks = ThunkTable(functions)
        self.original_first_thunk_rva = 0
        self.first_thunk_rva = 0
        self.name_rva = 0
        self.thunk_names_rva = 0

    def write(self):
        return (uint32(self.original_first_thunk_rva) +
                uint32(0) +  # time date stamp
                uint32(0) +  # forwarder chain
                uint32(self.name_rva) +
                uint32(self.first_thunk_rva))


class ImportAddressTables(object):
    def __init__(self):
        self.module_names = set
        self.function_names = []

    def write(self, rva, functions):
        module_names = set(mod_name for mod_name, _ in functions)
        import_descriptors = []

        for module in module_names:
            func_names = [func_name for mod_name, func_name in functions if mod_name == module]
            import_descriptors += [ImageImportDescriptor(module, func_names)]

        idt_size_in_bytes = 20 * (len(import_descriptors) + 1)
        result = '\0' * idt_size_in_bytes  # empty space for idt

        for idt in import_descriptors:
            idt.name_rva = rva + len(result)
            result += idt.name + '\0'

        for idt in import_descriptors:
            idt.thunk_names_rva = rva + len(result)
            result += idt.thunks.write_names()

        for idt in import_descriptors:
            idt.original_first_thunk_rva = rva + len(result)
            result += idt.thunks.write_thunks(idt.thunk_names_rva)

        for idt in import_descriptors:
            idt.first_thunk_rva = rva + len(result)
            result += idt.thunks.write_thunks(idt.thunk_names_rva)

        idt_data = ''.join(idt.write() for idt in import_descriptors) + '\0' * 20

        return idt_data + result[idt_size_in_bytes:]


class PeRebuilder(object):
    def __init__(self, raw, code_rva=0x1000):
        try:
            self.pe = p.PE(data=str(raw))
        except p.PEFormatError:
            raw = self.memdump_to_pe(raw, code_rva)
            self.pe = p.PE(data=str(raw))

    def set_image_base(self, image_base):
        self.pe.OPTIONAL_HEADER.ImageBase = image_base

    def memdump_to_pe(self, raw, code_rva):
        pe = p.PE(asset_path('assets/template.exe'))

        for s in pe.sections:
            code_section = s
            s.PointerToRawData = 0x200
            break
        else:
            raise RuntimeError("No sections found")

        code_section.Characteristics = 0xE0000020
        code_section.SizeOfRawData = round_up(len(raw), 0x200)
        code_section.Misc_VirtualSize = round_up(len(raw), 0x1000)
        code_section.VirtualAddress = code_rva
        raw_start = code_section.PointerToRawData
        raw += (code_section.SizeOfRawData - len(raw)) * '\0'
        pe = p.PE(data=pe.write()[:raw_start] + raw)

        return pe.write()

    def rebuild_iat(self, functions):
        functions = list(set(functions))
        tmp_vaddr = 0x1000000
        tables = ImportAddressTables()
        iat_data = tables.write(tmp_vaddr, functions)
        sections = SectionDoubleP(self.pe)
        self.pe = sections.push_back(Name=".idata", VirtualAddress=tmp_vaddr, Data=iat_data)

        iat = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[1]
        iat.VirtualAddress = tmp_vaddr
        iat.Size = len(iat_data)

    def rebuild(self):
        return self.pe.write()


def main():
    # usage example

    import sys
    path = sys.argv[1]
    data = open(path, 'rb').read()

    rebuilder = PeRebuilder(data)

    rebuilder.set_image_base(0x830000)

    rebuilder.rebuild_iat([
        ('kernel32', 'GetProcAddress'),
        ('kernel32', 'ExitProcess'),
    ])

    result = rebuilder.rebuild()

    pe = p.PE(data=result)
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print entry.dll
        for imp in entry.imports:
            print '\t', hex(imp.address), imp.name

    # print self.name, self.original_first_thunk_rva, self.first_thunk_rva, self.name_rva
    # kernel32 16777292 16777310 16777256

    open(path + '.rebuild', 'wb').write(result)

if __name__ == '__main__':
    main()
