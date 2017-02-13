#!/usr/bin/python

import argparse

import printer

import keys
import nymaimlib
import nymcnclib
import nymcfglib
import pcapextract
import json


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('--quiet', '-q', action='store_true', help='be silent')
    parser.add_argument('--keyset', '-k', type=int, default=2, help='0, 1 or 2 - set of encryption keys to use')
    parser.add_argument('data', help='data to parse')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--pcap', '-p', action='store_true', help='parse pcap, extract webinjects and binaries')
    group.add_argument('--blob', '-b', action='store_true', help='parse raw blob, extract webinjects and binaries')
    group.add_argument('--response', '-r', action='store_true', help='parse raw response, extract webinjects and binaries')
    group.add_argument('--config', '-c', action='store_true', help='parse dump, extract static config')
    group.add_argument('--deobfuscate', '-d', action='store_true', help='deobfuscate dump, write deobfuscated file')
    group.add_argument('--decrypt-data', '-a', action='store_true', help='decrypt data section, write decrypted file back')
    group.add_argument('--communicate', '-m', action='store_true', help='download everything from cnc')

    return parser.parse_args()


def main():
    args = parse_args()

    if args.quiet:
        printer.config(True)

    rc4key, rsakey = keys.KEYS[args.keyset]

    if args.pcap:
        def callback(data, is_response):
            ctx = {'is_response': is_response}
            nymaimlib.parse_raw_response(data, ctx, rsakey, rc4key)

        pcapextract.parse_pcap_file(args.data, callback, None)
    elif args.blob:
        with open(args.data, 'rb') as data:
            nymaimlib.nymaim_blob_parse(data.read(), {'is_response': False}, rsakey)
    elif args.response:
        with open(args.data, 'rb') as data:
            nymaimlib.parse_raw_response(data.read(), {'is_response': False}, rsakey, rc4key)
    elif args.config:
        with open(args.data, 'rb') as data:
            cfg = nymcfglib.extract_config(data.read())
            print json.dumps(cfg, sort_keys=True, indent=2,separators=(',', ': '), ensure_ascii=False)
    elif args.deobfuscate:
        import deobfuscator.rules.nymaim as nymaimrls
        from deobfuscator.commons import Deobfuscator
        with open(args.data, 'rb') as data:
            raw = bytearray(data.read())
            rules = nymaimrls.all_rules
            deobfuscator = Deobfuscator(rules, path=args.data)
            raw = deobfuscator.deobfuscate(raw)
            open(args.data + '.deobfuscated', 'wb').write(raw)
    elif args.decrypt_data:
        from deobfuscator.rules.nymaim_base import decrypt_raw_all
        with open(args.data, 'rb') as data:
            nymaim = bytearray(data.read())
            plain = decrypt_raw_all(nymaim)
            open(args.data + '.decrypted', 'wb').write(plain)
    elif args.communicate:
        with open(args.data, 'rb') as data:
            cfg = json.loads(data.read())
            cfg['rc4_key'] = rc4key
            cfg['rsa_key'] = rsakey
            nymcnclib.communicate_as_payload(cfg)


if __name__ == '__main__':
    main()
