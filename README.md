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

### Help

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
  --pcap, -p            parse pcap capture, extract webinjects and binaries
  --blob, -b            parse raw message blob, extract webinjects and binaries
  --resp, -r            parse raw response, extract webinjects and binaries
  --conf, -c            parse unpacked memory dump, extract static config
```


Difference between --pcap, --resp and --blob:

* --pcap automatically splits .pcap file into tcp streams, and parses them independently
* --resp parses single tcp stream
* --blob parses single tcp stream after rc4 decryption

**Usage examples:**

Parse old .pcap capture file (with older keyset)

    ./nymaim.py --pcap /home/msm/PycharmProjects/NymaimCnC/datadump2.pcap --keyset=1

    [snip]

Parse memory dump

    ╰─$ ./nymaim.py --quiet --conf ~/nymaim_dumps/obfuscated/dropper_80007_2015-11-06_xxxxxxxx_xjxf_x_553bcd6ac24c63a288161e6364ed5cb3
    {
      "dns": [
        "8.8.8.8:53",
        "8.8.4.4:53"
      ],
      "domains": [
        {
          "cnc": "http://yckmgk.in"
        }
      ],
      [snip]
    }

In case of any questions, please email msm@cert.pl or info@cert.pl.
