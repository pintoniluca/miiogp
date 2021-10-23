import json
import sys
import zlib
import base45
import cbor2
from cose.messages import CoseMessage
#Use a QRCode reader to get the string called payload
#Remove Prefix HC1: from the obtained result
payload = '6BFOXN%TS3DHPVO13J /G-/2YRVA.Q/R8RNM2FC1J9M$DI9C9I9%NJDAIRJPC%OQHIZC4.OI1RM8ZA.A53XHMKN4NN3F85QNCY0O%0VZ001HOC9JU0D0HT0HB2PL/IB*09B9LW4T*8+DCSJ0%YBITH$*SBAKYE9*FJ7ID$0HY84:Y0W0MI 0X*262M8:I*/GC-D9-8Y2QK%4U1J63P84QL0HU+4./GPHN6D7LLK*2HG%89UVZ0L8I0CUHPVFNXUJRHQJA8RUEIAYQE*C2:JG*PEMN9FTIWMA-RI PQVW5/O10+HT+6SZ4RZ4E%5B/9BL50ZUNYH:NE31AYWP*PMYZQ4H99$R2-JIS77%F.UIH$UT.TFRMLNKNM8JI0EUGP$I/XK$M8-L96YB-EKYV5IR3UASNX2NNPXN2U1NW9V*QL$DLF+M2*E:F4* 4X4TIWL4DFYWPHQ6J97N5LQ5BV57GFJVW9$SCNF4X4W26SRBO MK4AVHZP4WKURDTY12-TU1F'#sys.argv[1][4:]
decoded = base45.b45decode(payload)
decompressed = zlib.decompress(decoded)
cosefile=open("greenpassfile.cose", "wb") #If you run from VSCode insert an absolute path like C:\\Users\\User\\Desktop\\HG\\greenpassfile.cose
cose = CoseMessage.decode(decompressed)
cosefile.write(decompressed)
cosefile.close()
print(json.dumps(cbor2.loads(cose.payload), indent=2))