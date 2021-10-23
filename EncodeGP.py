import json
import sys
import zlib
import base45
import cbor2
from cose.messages import CoseMessage
print("Coding in QRCODE: \r")
recoded=open("greenpassfile.cose", "rb") #If you run from VSCode insert an absolute path like C:\\Users\\User\\Desktop\\HG\\greenpassfile.cose
coseloya=recoded.read()
cosepress = zlib.compress(coseloya)
recoded.close()
convBase = base45.b45encode(cosepress)
print("HC1:")
print(convBase)