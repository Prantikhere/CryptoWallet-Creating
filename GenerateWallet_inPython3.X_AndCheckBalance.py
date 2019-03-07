from ecdsa import SigningKey, SECP256k1
import sha3
import sys
import re
import requests
import json
import os
import multiprocessing
import time
import os.path
import hashlib
p = multiprocessing.Pool(int(multiprocessing.cpu_count()))

from ecdsa import SigningKey, SECP256k1
import sha3
import urllib
proxy = {
    "http":"http://szl2sxj:January@2019@proxy.ups.com:8080",
    "https":"https://szl2sxj:January@2019@proxy.ups.com:8080"
}

wallets = 0
balance = '0'

def checksum_encode(addr_str): # Takes a hex (string) address as input
    keccak = sha3.keccak_256()
    out = ''
    addr = addr_str.lower().replace('0x', '')
    keccak.update(addr.encode('ascii'))
    hash_addr = keccak.hexdigest()
    for i, c in enumerate(addr):
        if int(hash_addr[i], 16) >= 8:
            out += c.upper()
        else:
            out += c
    return '0x' + out


keccak = sha3.keccak_256()
priv = SigningKey.generate(curve=SECP256k1)
pub = priv.get_verifying_key().to_string()
keccak.update(pub)
address = keccak.hexdigest()[24:]
KeyPriv = priv.to_string().hex()
KeyPub = pub.hex()
EtherAddr = checksum_encode(address)


def test(addrstr):
    assert(addrstr == checksum_encode(addrstr))

test('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed')
test('0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359')
test('0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB')
test('0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb')
test('0x7aA3a964CC5B0a76550F549FC30923e5c14EDA84')
#r = requests.get('https://api.etherscan.io/api?module=account&action=balance&address=' + EtherAddr + '&tag=latest&apikey=YourApiKeyToken', proxies = proxy )
#data = json.loads(r.text)
#balance = data['result']
#print("Private key:", priv.to_string().hex())
#print("Public key: ", pub.hex())
#print("Address:    ", checksum_encode(address))
#print(' Original PrivateKey :  %s' % KeyPriv)
#print(' Original PublicKey :  %s' % KeyPub)
#print(' Original EtherAddress :  %s' % EtherAddr, '\n' )
#r = requests.get('https://api.etherscan.io/api?module=account&action=balance&address=' + EtherAddr + '&tag=latest&apikey=YourApiKeyToken', proxies = proxy )


while balance <= '0':
	try:
		if len(sys.argv) > 1:
			arg1 = sys.argv[1]
			assert re.match(r"^[0-9a-fA-F]{1,10}$",arg1) != None
			searchstring = arg1.lower()
			listwide=4*int(multiprocessing.cpu_count())*2**len(searchstring)
			vanity = True
	except:
		raise ValueError("Error in argument, not a hex string or longer than 10 chars")
	# load_gtable('lib/G_Table')
if 'inter' not in locals():
		wallets = wallets + 1
		r = requests.get('https://api.etherscan.io/api?module=account&action=balance&address=' + EtherAddr + '&tag=latest&apikey=YourApiKeyToken', proxies = proxy )
		data = json.loads(r.text)
		balance = data['result']
        
		if balance > '0':
			print('Wallet Found!')
			print(' Balance is: %s\n' % balance)
			print("\nEtherKey_Balance_Address :  %s \n" % EtherAddr)
			print("PrivKey :  %s\n\n" % KeyPriv)
			privfileexist=False
			conf="n"
			if os.path.isfile('priv.key'):
				privfileexist=True
				conf=input("Enter 'y' to confirm overwriting priv.key file : ")
			if (conf=="y" or not privfileexist):
				with open('priv.key', 'wb') as f:
					f.write(KeyPriv)
				print("Private key exported in priv.key file")
		#print ' End of ',wallets,' searches, since Balance is 0\n\n\n\n'