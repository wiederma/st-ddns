#!/usr/bin/env python3

import ssl
from hashlib import sha256
import requests
from deviceID import get_device_id

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


def verify_host(host, exp_fp):
    cert = ssl.get_server_certificate((host, 443))
    v = ssl.PEM_cert_to_DER_cert(cert)
    digest = sha256(v).digest()
    fp = get_device_id(digest)
    if fp == exp_fp:
        return True
    return False


def announce():
    for mapping in pinning:
        disco_url = 'https://' + mapping[0]
        payload = {'addresses': ['tcp://:12345']}

        try:
            if verify_host(*mapping) is False:
                raise RuntimeError

            r = requests.post(
                disco_url,
                json=payload,
                verify=False,
                # TODO: Make this configurable
                cert=('./cert.pem', './key.pem'),
            )
        # verify_host() raises OSError
        except OSError:
            # TODO: Log a warning
            continue
        except requests.exceptions.ConnectionError:
            # TODO: Log a warning here
            continue

        if r.status_code != 204:
            # TODO: Log a warning
            continue

        reannounce_time = r.headers['Reannounce-After']
        print(reannounce_time)


def request():
    device_id = ''

    with open('./cert.pem') as f:
        v = ssl.PEM_cert_to_DER_cert(f.read())
        digest = sha256(v).digest()
        device_id = get_device_id(digest)

    request_url = 'https://announce.syncthing.net/v2/'

    # FIXME: Use urljoin and friends here.
    r = requests.get(request_url + '?device=' + device_id, verify=False)
    ip = r.text.split(':')[5].rsplit('/')[2]
    print(ip)


def main():
    announce()
    # request()


if __name__ == '__main__':
    main()
