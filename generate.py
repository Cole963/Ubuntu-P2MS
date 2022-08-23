from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import binascii
import random

key = DSA.generate(2048)

public_key = key.publickey().export_key()


param_key = DSA.import_key(public_key)
param = [param_key.p, param_key.q, param_key.g]

# Generate 4 keys
key1 = DSA.generate(2048, domain=param)
pubkey1 = key1.publickey().export_key()
pubkey1 = binascii.hexlify(pubkey1)

key2 = DSA.generate(2048, domain=param)
pubkey2 = key2.publickey().export_key()
pubkey2 = binascii.hexlify(pubkey2)

key3 = DSA.generate(2048, domain=param)
pubkey3 = key3.publickey().export_key()
pubkey3 = binascii.hexlify(pubkey3)

key4 = DSA.generate(2048, domain=param)
pubkey4 = key4.publickey().export_key()
pubkey4 = binascii.hexlify(pubkey4)


# Write to pubkey file

string = "OP_2[" + str(pubkey1.decode()) + "][" + str(pubkey2.decode()) + "][" + str(pubkey3.decode()) + "][" + str(pubkey4.decode()) + "]OP_4OP_CHECKMULTISIG"



#print(DSA.import_key(str(key1)))
filewrite = open("scriptPubKey.txt", "w")
filewrite.write(string)
filewrite.close()

# RNG to decide which pubkey to use

numArr = [1, 2, 3, 4]
firstKey = random.choice(numArr)
numArr.remove(firstKey)
secondKey = random.choice(numArr)

if firstKey > secondKey:
	temp = firstKey
	firstKey = secondKey
	secondKey = temp

# Generate signatues
# Skipped 4 because first Sig will never use the last pub key
message = b"Contemporary topic in security"
hash_obj = SHA256.new(message)

if firstKey == 1:
	signer = DSS.new(key1, 'fips-186-3')

elif firstKey == 2:	
	signer = DSS.new(key2, 'fips-186-3')

elif firstKey == 3:
	signer = DSS.new(key3, 'fips-186-3')


signature1 = signer.sign(hash_obj)
signature_hex1 = binascii.hexlify(signature1)

# Skipped 1 because second sig will never use first pub key

if secondKey == 2:
	signer = DSS.new(key2, 'fips-186-3')

elif secondKey == 3:
	signer = DSS.new(key3, 'fips-186-3')

elif secondKey == 4:
	signer = DSS.new(key4, 'fips-186-3')


signature2 = signer.sign(hash_obj)
signature_hex2 = binascii.hexlify(signature2)


# Remove prepends and appends of the sigs
signature_hex1 = str(signature_hex1)[2:]
signature_hex1 = signature_hex1[:-1]
signature_hex2 = str(signature_hex2)[2:]
signature_hex2 = signature_hex2[:-1]

string = "OP_1[" + signature_hex1 + "][" + signature_hex2 + "]"

# Write to scriptSig.txt

filewrite = open("scriptSig.txt", "w")
filewrite.write(string)
filewrite.close()


print("scriptPubKey.txt and scriptSig.txt created")




