from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import binascii
import random


# Read sig file

sigRead = open("scriptSig.txt", "r")
scriptSig = sigRead.read()
sigRead.close()

# Read pubkey file

keyRead = open("scriptPubKey.txt", "r")
scriptKey = keyRead.read()
keyRead.close()

fullScript = scriptSig + scriptKey

sigCutOff = fullScript[4:].find("OP")

sigSegment = fullScript[:sigCutOff+4]
keySegment = fullScript[sigCutOff+4:]

# Creation of stack and printing
stack = []
print("\nInitial Stack contents: ")
print(stack)

# Get value of first OP and add to stack
cutOff = sigSegment.find("[")
op = sigSegment[:cutOff] 
sigSegment = sigSegment[cutOff:]
stack.append(op[3:])

# Loop the signatures and add them to stack
while(sigSegment.find("]") != -1):
	cutOff = sigSegment.find("]")
	sig = sigSegment[:cutOff+1]
	sigSegment = sigSegment[cutOff+1:]
	stack.append(sig[1:-1])

# Print stack contents after current process
print("\nStack contents after signatures are added: ")
print(stack)


# Get value of first OP and add to stack
cutOff = keySegment.find("[")
op = keySegment[:cutOff]
keySegment = keySegment[cutOff:]
stack.append(op[3:])

# Loop the keys and add them to stack
while(keySegment.find("]") != -1):
	cutOff = keySegment.find("]")
	key = keySegment[:cutOff+1]
	keySegment = keySegment[cutOff+1:]
	stack.append(key[1:-1])

# Get OP value and add to stack
cutOff = keySegment.find("OP_CHECKMULTISIG")
op = keySegment[:cutOff]
keySegment = keySegment[cutOff:]
stack.append(op[3:])

print("\nStack contents after keys are added: ")
print(stack)

# Start popping 
noOfKeys = stack.pop()
keyList = []
for i in range(int(noOfKeys)):
	keyList.insert(0, stack.pop())

noOfSigs = stack.pop()
sigList = []
for i in range(int(noOfSigs)):
	sigList.insert(0, stack.pop())

print("\nStack contents after signatures and keys are popped: ")
print(stack) 
print()
# Unhexlifies the signatures 
for i in range(len(sigList)):
	sigList[i] = binascii.unhexlify(sigList[i].encode())
	

# Unhexlifies and imports the DSA keys
for i in range(len(keyList)):
	keyList[i] = DSA.import_key(binascii.unhexlify(keyList[i]))


hash_obj = SHA256.new(b"Contemporary topic in security")
correctKey = -1

for j in range(len(sigList)):
	for i in range(len(keyList)):
		if(i <= correctKey):
			continue
		verifier = DSS.new(keyList[i] , 'fips-186-3')

		try:
			verifier.verify(hash_obj, sigList[j])
			print("The message derived from PubKey" + str(i+1) + " and Sig" + str(j+1) + " is authentic.")
			correctKey = i
			break
		except ValueError:
			print("The message derived from PubKey" + str(i+1) + " and Sig" + str(j+1) + " is not authentic. ")




