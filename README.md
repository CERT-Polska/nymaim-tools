# Nymaim-tools

This is a set of tools we have created for analysis and tracking Nymaim trojan.

A word of warning:
This repository is amalgam of various loosely matching scripts, that we hacked into single
repository at the last minute. We never used this repository as is, instead we
compiled this set from a lot of independent scripts scattered all over our internal system.

### nymaimlib.py

Scripts for parsing Nymaim network communication, requests and responses.

### nymcnclib.py

Scripts implementing C&C/peer communication. Depends on nymaimlib.

Not available publicly (contact us if you're interested).

### nymcfglib.py

Parser for nymaim's static configuration.

### nymaim.py

Main file, command line interface for other scripts.

```
╰─$ ./nymaim.py --help
usage: nymaim.py [-h] [--quiet] [--keyset KEYSET]
                 (--pcap | --blob | --resp | --conf)
                 data

positional arguments:
  data                  data to parse

optional arguments:
  -h, --help            show this help message and exit
  --quiet, -q           be silent
  --keyset KEYSET, -k KEYSET
                        0, 1 or 2 - set of encryption keys to use
  --pcap, -p            parse pcap, extract webinjects and binaries
  --blob, -b            parse raw blob, extract webinjects and binaries
  --resp, -r            parse raw response, extract webinjects and binaries
  --conf, -c            parse dump, extract static config
```

In case of any questions, please email msm@cert.pl or info@cert.pl.
