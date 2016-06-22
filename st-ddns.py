#!/usr/bin/env python3

import sys
import requests
import ssl
from deviceID import *

key = 'url'
value = 'hostID'

# ID pinning to host
hostIDs = [
{key:'discovery-v4-1.syncthing.net', value:'SR7AARM-TCBUZ5O-VFAXY4D-CECGSDE-3Q6IZ4G-XG7AH75-OBIXJQV-QJ6NLQA'},
{key:'test', value:'bla'},
]

def verifyHost(host):
	cert = ssl.get_server_certificate((host, 443))
	v = ssl.PEM_cert_to_DER_cert(cert)
	digest = sha256(v).digest()
	hostID=get_device_id(digest)
	print(hostID)
	return hostID

# announce
def announce():
	"""
	"""
	announce_url='https://discovery-v4-1.syncthing.net/v2/?id=SR7AARM-TCBUZ5O-VFAXY4D-CECGSDE-3Q6IZ4G-XG7AH75-OBIXJQV-QJ6NLQA'

	announce_request = requests.post(announce_url, json={ 'addresses': ['tcp://:22202']}, verify=False, cert=('./cert.pem', './key.pem') )

	print(announce_request.status_code)

	if announce_request.status_code == 204:
		pass
	else:
		print('Announcemnet failed')
		sys.exit

	reannounce_time = announce_request.headers['Reannounce-After']
	print(reannounce_time)

# request
def request():
	"""
	"""
	deviceID=''

	with open('./cert.pem') as f:
		v = ssl.PEM_cert_to_DER_cert(f.read())
		digest = sha256(v).digest()
		deviceID=get_device_id(digest)

	request_url='https://announce.syncthing.net/v2/'

	r = requests.get(request_url + '?device=' + deviceID, verify=False)
	ip = r.text.split(':')[5].rsplit('/')[2]
	print(ip)

def main():
	"""

	"""
	#announce()
	#request()

	for i in range(0,len(hostIDs)):
		print(hostIDs[i][key])

	hID = verifyHost(hostIDs[0][key])
	if hID == hostIDs[0][value]:
		print('IDs match')
	else:
		print('IDs dont match')

if __name__ == '__main__':
	main()
