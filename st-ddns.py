#!/usr/bin/env python3

import requests
import ssl
from hashlib import sha256
from deviceID import get_device_id

# ID pinning to host
pinning = (
    (
        'discovery-v4-1.syncthing.net',
        'SR7AARM-TCBUZ5O-VFAXY4D-CECGSDE-3Q6IZ4G-XG7AH75-OBIXJQV-QJ6NLQA',
    ),
)


def verify_host(host):
    cert = ssl.get_server_certificate((host, 443))
    v = ssl.PEM_cert_to_DER_cert(cert)
    digest = sha256(v).digest()
    hostID = get_device_id(digest)
    print(hostID)
    return hostID


def announce():
    # FIXME: generate this from pinning tuples
    announce_url = 'https://discovery-v4-1.syncthing.net/v2/?id=SR7AARM-TCBUZ5O-VFAXY4D-CECGSDE-3Q6IZ4G-XG7AH75-OBIXJQV-QJ6NLQA'

    payload = {'addresses': ['tcp://:12345']}
    r = requests.post(
        announce_url,
        json=payload,
        verify=False,
        # TODO: Make this configurable
        cert=('./cert.pem', './key.pem'),
    )

    print(r.status_code)

    if r.status_code == 204:
        pass
    else:
        print('Announcemnet failed')
        exit()

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
    # announce()
    # request()

    fp = verify_host(pinning[0][0])

    if fp == pinning[0][1]:
        print('IDs match')
    else:
        print('IDs dont match')


if __name__ == '__main__':
    main()
