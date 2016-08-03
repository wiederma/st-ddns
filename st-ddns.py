#!/usr/bin/env python3

import argparse
import base64
import ssl
import sys
from hashlib import sha256
from subprocess import run
import shlex
import logging
import requests


# We do the pinning ourselves; we don't need a monkey
# who warns us all the time that we are not safe...
# http://stackoverflow.com/a/28002687
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# fingerprint pinning to host
pinning = (
    (
        'discovery-v4-1.syncthing.net',
        'SR7AARM-TCBUZ5O-VFAXY4D-CECGSDE-3Q6IZ4G-XG7AH75-OBIXJQV-QJ6NLQA',
    ),
    (
        'discovery-v4-2.syncthing.net',
        'DVU36WY-H3LVZHW-E6LLFRE-YAFN5EL-HILWRYP-OC2M47J-Z4PE62Y-ADIBDQC',
    ),
    (
        'discovery-v4-3.syncthing.net',
        'VK6HNJ3-VVMM66S-HRVWSCR-IXEHL2H-U4AQ4MW-UCPQBWX-J2L2UBK-NVZRDQZ',
    ),
    (
        'discovery-v6-1.syncthing.net',
        'SR7AARM-TCBUZ5O-VFAXY4D-CECGSDE-3Q6IZ4G-XG7AH75-OBIXJQV-QJ6NLQA',
    ),
    (
        'discovery-v6-2.syncthing.net',
        'DVU36WY-H3LVZHW-E6LLFRE-YAFN5EL-HILWRYP-OC2M47J-Z4PE62Y-ADIBDQC',
    ),
    (
        'discovery-v6-3.syncthing.net',
        'VK6HNJ3-VVMM66S-HRVWSCR-IXEHL2H-U4AQ4MW-UCPQBWX-J2L2UBK-NVZRDQZ',
    ),
)


def _luhn_mod_sum(s):
    # https://en.wikipedia.org/wiki/Luhn_mod_N_algorithm
    a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    n = len(a)
    factor = 1
    k = 0
    for i in s:
        addend = factor * a.index(i)
        factor = 1 if factor == 2 else 2
        addend = (addend // n) + (addend % n)
        k += addend
    remainder = k % n
    check_codepoint = (n - remainder) % n
    return a[check_codepoint]


def _chunk_str(s, chunk_size):
    return [s[i:i+chunk_size] for i in range(0, len(s), chunk_size)]


def _hash_cert_bin(cert):
    v = ssl.PEM_cert_to_DER_cert(cert)
    return sha256(v).digest()


def _hash_cert_file(path):
    logging.debug('Reading certificate: {}'.format(path))
    with open(path) as f:
        return _hash_cert_bin(f.read())


def calc_device_id(barray):
    s = ''.join([chr(a) for a in base64.b32encode(barray)][:52])
    c = _chunk_str(s, 13)
    k = ''.join(['%s%s' % (cc, _luhn_mod_sum(cc)) for cc in c])
    return '-'.join(_chunk_str(k, 7))


def verify_host(host, exp_fp):
    cert = ssl.get_server_certificate((host, 443))
    fp = calc_device_id(_hash_cert_bin(cert))
    if fp == exp_fp:
        return True
    return False


#
# Commands
#
def cmd_announce(args):
    cert = shlex.quote(args.cert)
    key = shlex.quote(args.key)

    logging.debug('Using certificate: {}'.format(cert))
    logging.debug('Using key: {}'.format(key))

    for mapping in pinning:
        disco_url = 'https://' + mapping[0] + '/v2/' + '?id=' + mapping[1]
        payload = {'addresses': ['tcp://:12345']}

        try:
            if verify_host(*mapping) is False:
                raise RuntimeError

            r = requests.post(
                disco_url,
                json=payload,
                verify=False,
                cert=(cert, key),
            )

        # requests does logging through the enabled logging module
        except OSError:
            continue
        except requests.exceptions.ConnectionError:
            continue

        if r.status_code != 204:
            logging.info('Announce failed')
            logging.debug(r.text)
            continue


def cmd_request(args):
    device_id = calc_device_id(_hash_cert_file(args.cert))
    request_url = 'https://announce.syncthing.net/v2/'

    # FIXME: Use urljoin and friends here.
    r = requests.get(request_url + '?device=' + device_id, verify=False)
    if r.status_code != 200:
        logging.info('No device found!')
        logging.debug(r.text)
        exit(1)

    ip = r.text.split(':')[5].rsplit('/')[2]
    print(ip)


def cmd_gencert(args):
    run([
        'openssl',
        'req',
        '-x509',
        '-newkey',
        'rsa:4096',
        '-keyout',
        'key.pem',
        '-out',
        'cert.pem',
        '-nodes',
    ])


def cmd_fingerprint(args):
    device_id = calc_device_id(_hash_cert_file(args.cert))
    print(device_id)


def logging_init(loglevel):
    # From python docs. No magic stackoverflow involved. :)
    # https://docs.python.org/3/howto/logging.html#logging-to-a-file
    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        print('Invalid log level: "{}"'.format(loglevel))
        exit(1)

    logging.basicConfig(
        format='%(asctime)s %(levelname)s: %(message)s',
        level=numeric_level,
    )


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-c',
        '--cert',
        default='./cert.pem',
        help='Use this certificate [default: ./cert.pem]',
    )
    parser.add_argument(
        '-k',
        '--key',
        default='./key.pem',
        help='Use this private key [default: ./key.pem]',
    )
    parser.add_argument(
        '-l',
        metavar='LEVEL',
        type=str,
        default='WARNING',
        help='CRITICAL, ERROR, WARNING [default], INFO, DEBUG'
    )

    subparsers = parser.add_subparsers()
    parser_announce = subparsers.add_parser(
        'announce',
        aliases=('ann',),
        help='Announce IP to the Syncthing discovery system',
    )
    parser_announce.set_defaults(func=cmd_announce)

    parser_request = subparsers.add_parser(
        'request',
        aliases=('req',),
        help='Query the ip of a given device',
    )
    parser_request.add_argument('ID')
    parser_request.set_defaults(func=cmd_request)

    parser_gencert = subparsers.add_parser(
        'gencert',
        aliases=('gc',),
        help='Generate a certificate',
    )
    parser_gencert.set_defaults(func=cmd_gencert)

    parser_fingerprint = subparsers.add_parser(
        'fingerprint',
        aliases=('fp',),
        help='Print the fingerprint of a given certificate',
    )
    parser_fingerprint.add_argument(
        'cert',
        help='The path to the certificate file',
    )
    parser_fingerprint.set_defaults(func=cmd_fingerprint)

    return parser.parse_args()


def main():
    args = parse_args()
    logging_init(args.l)
    logging.debug('Invoked with args: {}'.format(args))

    if hasattr(args, 'func'):
        args.func(args)


if __name__ == '__main__':
    main()
