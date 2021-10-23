package dgca.verifier.app.decoder

import COSE.HeaderKeys
import android.annotation.TargetApi
import android.os.Build
import android.util.Base64.*
import com.fasterxml.jackson.databind.*
import com.upokecenter.cbor.CBORObject
import dgca.verifier.app.decoder.base45.Base45Decoder
import dgca.verifier.app.decoder.base45.Base45Service
import dgca.verifier.app.decoder.base45.DefaultBase45Service
import dgca.verifier.app.decoder.cbor.CborService
import dgca.verifier.app.decoder.cbor.DefaultCborService
import dgca.verifier.app.decoder.cbor.DefaultGreenCertificateMapper
import dgca.verifier.app.decoder.cbor.GreenCertificateMapper
import dgca.verifier.app.decoder.compression.CompressorService
import dgca.verifier.app.decoder.compression.DefaultCompressorService
import dgca.verifier.app.decoder.cose.CoseService
import dgca.verifier.app.decoder.cose.CryptoService
import dgca.verifier.app.decoder.cose.DefaultCoseService
import dgca.verifier.app.decoder.cose.VerificationCryptoService
import dgca.verifier.app.decoder.cwt.CwtHeaderKeys
import dgca.verifier.app.decoder.model.CoseData
import dgca.verifier.app.decoder.model.GreenCertificate
import dgca.verifier.app.decoder.model.VerificationResult
import dgca.verifier.app.decoder.prefixvalidation.DefaultPrefixValidationService
import dgca.verifier.app.decoder.prefixvalidation.PrefixValidationService
import dgca.verifier.app.decoder.schema.DefaultSchemaValidator
import dgca.verifier.app.decoder.schema.SchemaValidator
import dgca.verifier.app.decoder.services.X509
import org.bouncycastle.asn1.*
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.*
import java.io.Closeable.*
import java.math.BigInteger
import java.security.*
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.*
import java.util.*
import java.util.zip.*
import javax.crypto.*
import kotlin.collections.ArrayList

private val greenCertificateMapper: GreenCertificateMapper = DefaultGreenCertificateMapper();

internal val CH_ET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:".toCharArray()
internal const val CH_ET_LENGTH = 45
internal const val CH_ET_LENGTH_SQUARED = 45 * 45

internal const val MIN_CH_VAL = 32
internal const val REVERSE_CH_SI = 59
internal val REVERSE_CH_ET = intArrayOf(
    36, -1, -1, -1, 37, 38, -1, -1, -1, -1,
    39, 40, -1, 41, 42, 43, 0, 1, 2, 3,
    4, 5, 6, 7, 8, 9, 44, -1, -1, -1,
    -1, -1, -1, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 33, 34, 35
)

private fun ByteArray.decompressBase45DecodedData(): ByteArray {
    // ZLIB magic headers
    return if (this.size >= 2 && this[0] == 0x78.toByte() && (
                this[1] == 0x01.toByte() || // Level 1
                        this[1] == 0x5E.toByte() || // Level 2 - 5
                        this[1] == 0x9C.toByte() || // Level 6
                        this[1] == 0xDA.toByte()
                )
    ) {
        //My actual input is 0x9C per this[1]
        InflaterInputStream(this.inputStream()).readBytes()
    } else this
}

private fun ByteArray.decodeCose(): CoseData {
    val messageObject = CBORObject.DecodeFromBytes(this)
    val content = messageObject[2].GetByteString() //CBOR
    val rgbProtected = messageObject[0].GetByteString()
    val rgbUnprotected = messageObject[1]
    val key = HeaderKeys.KID.AsCBOR()
    if (!CBORObject.DecodeFromBytes(rgbProtected).keys.contains(key)) {
        val objunprotected = rgbUnprotected.get(key).GetByteString()//KID
        return CoseData(content, objunprotected)//cbor, kid
    }
    val objProtected = CBORObject.DecodeFromBytes(rgbProtected).get(key).GetByteString()//KID
    return CoseData(content, objProtected)
}

private fun ByteArray.decodeGreenCertificate(): GreenCertificate {
    val map = CBORObject.DecodeFromBytes(this) //map: {4: 1683880017, 6: 1622973252, 1: "GR", -260: {1: {"t": [{"sc"....
    val hcert = map[CwtHeaderKeys.HCERT.asCBOR()] //hcert: {1: {"t": [{"sc"...
    val cborObject = hcert[CBORObject.FromObject(1)] //cborObj: {"t": [{"sc"...
    return greenCertificateMapper.readValue(cborObject)
}

private fun GreenCertificate.encodeCertificate(original:ByteArray): ByteArray{
    var obm: ObjectMapper = ObjectMapper()
    var map = CBORObject.DecodeFromBytes(original) //map: {4: 1683880017, 6: 1622973252, 1: "GR", -260: {1: {"t": [{"sc"....
    var hcert = map[CwtHeaderKeys.HCERT.asCBOR()] //hcert: {1: {"t": [{"sc"...
    var orCBO = hcert[CBORObject.FromObject(1)] //orCBO: {"t": [{"sc"...
    //I need to retrive a CborObject from a GreenCertificate
    //To greenCertificateMappe it's passed orCBO.toByteArray
    var cbo = CBORObject.FromObject(orCBO.toString())
    hcert[CBORObject.FromObject(1)] = cbo
    map[CwtHeaderKeys.HCERT.asCBOR()] = hcert
    return map.EncodeToBytes()
}

private fun CoseData.encodeCose(decompressed: ByteArray): ByteArray {
    var messageObject = CBORObject.DecodeFromBytes(decompressed)
    var rgbProtected = messageObject[0].GetByteString()
    val rgbUnprotected = messageObject[1]
    val content = messageObject[2].GetByteString() //CBOR
    val key = HeaderKeys.KID.AsCBOR()
    messageObject.RemoveAt(2)
    if (!CBORObject.DecodeFromBytes(rgbProtected).keys.contains(key)) {
        messageObject.RemoveAt(1)
        messageObject.Insert(1,rgbUnprotected.Set(key,CBORObject.FromObject(this.kid))) //Maybe this doesn't work!
    }else{
        var newKid = CBORObject.DecodeFromBytes(rgbProtected)
        newKid.set(key,CBORObject.FromObject(this.kid))
        rgbProtected = newKid.EncodeToBytes()
        messageObject.RemoveAt(0)
        messageObject.Insert(0,rgbProtected)
    }
    messageObject.Insert(2,this.cbor)
    return messageObject.EncodeToBytes()
}

private fun ByteArray.compressBase45DecodedData(): ByteArray {
    return DeflaterInputStream(this.inputStream()).readBytes()
}

private fun MutableList<Byte>.replaceString(find: String, replace: String): MutableList<Byte> {
    var index = 0
    var lfin=find.length
    var lrep=replace.length
    var i=0
    var j=0
    var two=0
    for(b in this){
        if(b==find[0].toByte()){
            if(this[i+1]==find[1].toByte() && this[i+2]==find[2].toByte()){
                index = i
            }
        }
        i++
    }
    j=0
    i = index
    if(i!=0){
        if(lfin<lrep){
            do{
                this[i] = replace[j].toByte()
                i++
                j++
            }while(j<lfin)
            do {
                this.add(i, replace[j].toByte())
                i++
                j++
            }while(j<lrep)
        }else{
            if(lfin==lrep){
                do{
                    this[i] = replace[j].toByte()
                    i++
                    j++
                }while(j<lrep)
            }else{
                do{
                    this[i] = replace[j].toByte()
                    i++
                    j++
                }while(j<lrep)
                j--
                do{
                    this.removeAt(i)
                    i++
                    j++
                }while(j<lfin-2)
            }
        }
    }
    return this
}

private fun ByteArray.encodeBase45(): String {
    val map = CH_ET
    val dataSize = size
    val lastGroupSize = dataSize % 2
    val length = dataSize / 2 * 3 + if (lastGroupSize != 0) 2 else 0
    val out = CharArray(length)
    val end = dataSize - lastGroupSize
    var index = 0
    var i = 0

    while (i < end) {
        val v = (this[i++].toInt() and 0xFF shl 8) + (this[i++].toInt() and 0xFF)
        val remainder = v % CH_ET_LENGTH_SQUARED
        val e = v / CH_ET_LENGTH_SQUARED
        val c = remainder % CH_ET_LENGTH
        val d = remainder / CH_ET_LENGTH
        out[index++] = map[c]
        out[index++] = map[d]
        out[index++] = map[e]
    }

    if (lastGroupSize == 1) {
        val a = this[i].toInt() and 0xFF
        val c = a % CH_ET_LENGTH
        val d = (a - c) / CH_ET_LENGTH
        out[index++] = map[c]
        out[index] = map[d]
    }

    return out.concatToString()
}

@TargetApi(Build.VERSION_CODES.O)
private fun toCertificate(pubKey: String?): X509Certificate {
    val `in` = Base64.getDecoder().decode(pubKey)
    val inputStream: InputStream = ByteArrayInputStream(`in`)
    return CertificateFactory.getInstance("X.509")
        .generateCertificate(inputStream) as X509Certificate
}

private fun verify(prefix: String?, PublicKey: String?): Boolean {
    val result = VerificationResult()
    val b45Service: Base45Service = DefaultBase45Service()
    val prefService: PrefixValidationService = DefaultPrefixValidationService()
    val compressorService: CompressorService = DefaultCompressorService()
    val validator: SchemaValidator = DefaultSchemaValidator()
    val coseservice: CoseService = DefaultCoseService()
    val greenCertificateMapper: GreenCertificateMapper = DefaultGreenCertificateMapper()
    val cborservice: CborService = DefaultCborService(greenCertificateMapper)
    val base45 = prefService.decode(prefix!!, result)
    val compressed = b45Service.decode(base45, result)
    val cose: ByteArray = compressorService.decode(compressed, result)!!
    val cbor = coseservice.decode(cose, result)
    val greenCertificate = cborservice.decode(cbor!!.cbor, result)
    val schemaresult = validator.validate(cbor.cbor, result)
    val cryptoService: CryptoService = VerificationCryptoService(X509())
    try {
        val cert: X509Certificate = toCertificate(PublicKey)
        //NOTE: The only different thing after a modify of COSE it's only COSE.
        cryptoService.validate(cose, cert, result, greenCertificate!!.getType())
    } catch (ex: Exception) {
        return false
    }
    return result.isValid()
}

@TargetApi(Build.VERSION_CODES.O)
private fun readSignInASN1DER(sign: ByteArray): ASN1Sequence? {
    var signatureHex = Base64.getEncoder().encodeToString(sign)
    //extracting r and s
    val first32SignatureBytes: ByteArray =
        Arrays.copyOfRange(Base64.getDecoder().decode(signatureHex), 0, 32)
    val signaturePartR: String = Base64.getEncoder().encodeToString(first32SignatureBytes)
    val last32SignatureBytes: ByteArray =
        Arrays.copyOfRange(Base64.getDecoder().decode(signatureHex), 32, 64)
    val signaturePartS: String = Base64.getEncoder().encodeToString(last32SignatureBytes)
    //converting r and s to asn1 and putting them in sequence
    val r = ASN1Integer(BigInteger(signaturePartR, 16))
    val s = ASN1Integer(BigInteger(signaturePartS, 16))
    val seq: ASN1Sequence = DERSequence(arrayOf<ASN1Encodable>(r, s))
    return seq
}

private fun convToDer(sign:ByteArray):ByteArray{
    var dIS: DerInputStream = DerInputStream(sign)
    var vals: Array<DerValue> = dIS.getSequence(2);
    var rm: ByteArray = vals[0].getPositiveBigInteger().toByteArray();
    var sgr: ByteArray = vals[1].getPositiveBigInteger().toByteArray();
    var tokSig: ByteArray = ByteArray(64)
    var pos = 0
    var pos2 = 0
    var pos3 = rm.size
    if(rm.size>32){
        pos = 1
        pos3 = 32
    }
    if(rm.size<32){
        pos2=1
    }
    System.arraycopy(rm,pos,tokSig,pos2,pos3)
    if(sgr.size>32){
        pos = 1
        pos3=32
    }else{
        pos = 0
        pos3=sgr.size
    }
    if(sgr.size<32){
        pos2=33
    }else{
        pos2=32
    }
    System.arraycopy(sgr,pos,tokSig,pos2,pos3)
    return tokSig;
}

@TargetApi(Build.VERSION_CODES.O)
@ExperimentalStdlibApi
private fun main(){
    println("From github.com/jojo2234/GreenPass-Experiments")
    println("------CMD PROGRAM TO VALIDATE GREEN PASS------")
    println("\nTo get the QR Code in ASCII text you can use programs like QR Code Reader")
    println("To create a new QR Code from ASCII text you can use programs like qtZint\n")
    println("Hello, insert the QR Code in ASCII text (remove \\) : ")

    var inpt = "HC1:NCFOXNEG2NBJ5*H:QO-.OMBN+XQ99N*6RFS5*TCVWBM*4ODMS0NSRHAL9.4I92P*AVAN9I6T5XH4PIQJAZGA2:UG%U:PI/E2$4JY/KB1TFTJ:0EPLNJ58G/1W-26ALD-I2"+'$'+"VFVVE.80Z0 /KY.SKZC*0K5AFP7T/MV*MNY"+'$'+"N.R6 7P45AHJSP"+'$'+"I/XK"+'$'+"M8TH1PZB*L8/G9HEDCHJ4OIMEDTJCJKDLEDL9CVTAUPIAK29VCN 1UTKFYJZJAPEDI.C"+'$'+"JC7KDF9CFVAPUB1VCSWC%PDMOLHTC"+'$'+"JC3EC66CTS89B9F$8H.OOLI7R3Y+95AF3J6FB5R8QMA70Z37244FKG6T"+'$'+"FJ7CQRB0R%5 47:W0UFJU.UOJ98J93DI+C0UEE-JEJ36VLIWQHH"+'$'+"QIZB%+N+Y2AW2OP6OH6XO9IE5IVU"+'$'+"P26J6 L6/E2US2CZU:80I7JM7JHOJKYJPGK:H3J1D1I3-*TW CXBD+$3PY2C725SS+TDM"+'$'+"SF*SHVT:5D79U+GC5QS+3TAQS:FLU+34IU*9VY-Q9P9SEW-AB+2Q2I56L916CO8T C609O1%NXDU-:R4TICQA.0F2HFLXLLWI8ZU53BMQ2N U:VQQ7RWY91SV2A7N3WQ9J9OAZ00RKLB2"
    try{
        inpt = readLine().toString()
        if(inpt=="" || inpt =="\n" || inpt=="\r\n"){
            inpt = "HC1:NCFOXNEG2NBJ5*H:QO-.OMBN+XQ99N*6RFS5*TCVWBM*4ODMS0NSRHAL9.4I92P*AVAN9I6T5XH4PIQJAZGA2:UG%U:PI/E2$4JY/KB1TFTJ:0EPLNJ58G/1W-26ALD-I2"+'$'+"VFVVE.80Z0 /KY.SKZC*0K5AFP7T/MV*MNY"+'$'+"N.R6 7P45AHJSP"+'$'+"I/XK"+'$'+"M8TH1PZB*L8/G9HEDCHJ4OIMEDTJCJKDLEDL9CVTAUPIAK29VCN 1UTKFYJZJAPEDI.C"+'$'+"JC7KDF9CFVAPUB1VCSWC%PDMOLHTC"+'$'+"JC3EC66CTS89B9F$8H.OOLI7R3Y+95AF3J6FB5R8QMA70Z37244FKG6T"+'$'+"FJ7CQRB0R%5 47:W0UFJU.UOJ98J93DI+C0UEE-JEJ36VLIWQHH"+'$'+"QIZB%+N+Y2AW2OP6OH6XO9IE5IVU"+'$'+"P26J6 L6/E2US2CZU:80I7JM7JHOJKYJPGK:H3J1D1I3-*TW CXBD+$3PY2C725SS+TDM"+'$'+"SF*SHVT:5D79U+GC5QS+3TAQS:FLU+34IU*9VY-Q9P9SEW-AB+2Q2I56L916CO8T C609O1%NXDU-:R4TICQA.0F2HFLXLLWI8ZU53BMQ2N U:VQQ7RWY91SV2A7N3WQ9J9OAZ00RKLB2"
        }
    }catch(e: Exception){
        println("Error, check inputs")
    }
    var dfv: DefaultPrefixValidationService = DefaultPrefixValidationService()
    var valid: VerificationResult = VerificationResult()
    var bd45 = Base45Decoder()
    //Decoding
    //NOTE: In real input are present $ or \ that could be illegal sometimes, you can insert them using concatenation for example: "FC1J9M"+'$'+"DI9C9I9" and you can remove backslash internal data are not modified and VerificaC19 detect the QRCode as valid
    var withoutPrefix = dfv.decode(inpt,valid)
    var zlibArchive = bd45.decode(withoutPrefix)
    var cosecborstring = zlibArchive.decompressBase45DecodedData()
    var coseStructured = cosecborstring.decodeCose() //The variable coseStructured it the selected one to be modified
    //Verify with public keys
    var readableGreenPass = coseStructured.cbor.decodeGreenCertificate()
    //println(coseStructured.cbor.decodeToString())
    println(readableGreenPass)
    var pubkey = "MIIBzDCCAXGgAwIBAgIUDN8nWnn8gBmlWgL3stwhoinVD5MwCgYIKoZIzj0EAwIwIDELMAkGA1UEBhMCR1IxETAPBgNVBAMMCGdybmV0LmdyMB4XDTIxMDUxMjExMjY1OFoXDTIzMDUxMjExMjY1OFowIDELMAkGA1UEBhMCR1IxETAPBgNVBAMMCGdybmV0LmdyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBcc6ApRZrh9/qCuMnxIRpUujI19bKkG+agj/6rPOiX8VyzfWvhptzV0149AFRWdSoF/NVuQyFcrBoNBqL9zCAqOBiDCBhTAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFN6ZiC57J/yRqTJ/Tg2eRspLCHDhMB8GA1UdIwQYMBaAFNU5HfWNY37TbdZjvsvO+1y1LPJYMDMGA1UdJQQsMCoGDCsGAQQBAI43j2UBAQYMKwYBBAEAjjePZQECBgwrBgEEAQCON49lAQMwCgYIKoZIzj0EAwIDSQAwRgIhAN6rDdE4mtTt2ZuffpZ242/B0lmyvdd+Wy6VuX+J/b01AiEAvME52Y4zqkQDuj2kbfCfs+h3uwYFOepoBP14X+Rd/VM="
    //var pubkey = "MIIFMDCCAxigAwIBAgIJAIZ9/G8KQie9MA0GCSqGSIb3DQEBDQUAMCUxIzAhBgNVBAMMGlRlc3QgT25seSBVbnNlY3VyZSBSb290IENBMB4XDTE4MDMyODAwMzIyM1oXDTM4MDMyMzAwMzIyM1owJTEjMCEGA1UEAwwaVGVzdCBPbmx5IFVuc2VjdXJlIFJvb3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDGxFNzAEyzSPmwE5gfuBXdXq++bl9Ep62V7Xn1UiejvmS+pRHT39pf/M7sl4Zr9ezanJTrFvf9+B85VGehdsD32TgfEjThcqaoQCI6pKkHYsUo7FZ5n+G3eE8oabWRZJMVo3QDjnnFYp7z20vnpjDofI2oQyxHcb/1yep+ca1+4lIvbUp/ybhNFqhRXAMcDXo7pyH38eUQ1JdKQ/QlBbShpFEqx1Y6KilKfTDf7Wenqr67LkaEim//yLZjlHzn/BpuRTrpo+XmJZx1P9CX9LGOXTtmsaCcYgD4yijOvV8aEsIJaf1kCIO558oH0oQc+0JG5aXeLN7BDlyZvH0RdSx5nQLS9kj2I6nthOw/q00/L+S6A0m5jyNZOAl1SY78p+wO0d9eHbqQzJwfEsSq3qGAqlgQyyjp6oxHBqT9hZtN4rxw+iq0K1S4kmTLNF1FvmIB1BE+lNvvoGdY5G0b6Pe4R5JFn9LV3C3PEmSYnae7iG0IQlKmRADIuvfJ7apWAVanJPJAAWh2Akfp8Uxr02cHoY6o7vsEhJJOeMkipaBHThESm/XeFVubQzNfZ9gjQnB9ZX2v+lyj+WYZSAz3RuXx6TlLrmWccMpQDR1ibcgyyjLUtX3kwZl2OxmJXitjuD7xlxvAXYob15N+K4xKHgxUDrbt2zU/tY0vgepAUg/xbwIDAQABo2MwYTAdBgNVHQ4EFgQUwyeNpYgsXXYvh9z0/lFrja7sV+swHwYDVR0jBBgwFoAUwyeNpYgsXXYvh9z0/lFrja7sV+swDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQENBQADggIBAGuOsvMN5SD3RIQnMJtBpcHNrxun+QFjPZFlYCLfIPrUkHpn5O1iIIq8tVLd2V+12VKnToUEANsYBD3MP8XjP+6GZ7ZQ2rwLGvUABKSX4YXvmjEEXZUZp0y3tIV4kUDlbACzguPneZDp5Qo7YWH4orgqzHkn0sD/ikO5XrAqmzc245ewJlrf+V11mjcuELfDrEejpPhi7Hk/ZNR0ftP737Hs/dNoCLCIaVNgYzBZhgo4kd220TeJu2ttW0XZldyShtpcOmyWKBgVseixR6L/3sspPHyAPXkSuRo0Eh1xvzDKCg9ttb0qoacTlXMFGkBpNzmVq67NWFGGa9UElift1mv6RfktPCAGZ+Ai8xUiKAUB0Eookpt/8gX9SenqyP/jMxkxXmHWxUu8+KnLvj6WLrfftuuD7u3cfc7j5kkrheDz3O4h4477GnqL5wdo9DuEsNc4FxJVz8Iy8RS6cJuW4pihYpM1Tyn7uopLnImpYzEY+R5aQqqr+q/A1diqogbEKPH6oUiqJUwq3nD70gPBUKJmIzS4vLwLouqUHEm1k/MgHV/BkEU0uVHszPFaXUMMCHb0iT9P8LuZ7Ajer3SR/0TRVApCrk/6OV68e+6k/OFpM5kcZnNMD5ANyBriTsz3NrDwSw4i4+Dsfh6A9dB/cEghw4skLaBxnQLQIgVeqCzK"
    //var pubkey = "MIIFDzCCAvegAwIBAgIQbNdueU2o0vM9gGq4N6bhjzANBgkqhkiG9w0BAQsFADAxMS8wLQYDVQQDEyZHb29nbGUgQ2xvdWQgS2V5IFZhdWx0IFNlcnZpY2UgUm9vdCBDQTAeFw0xODA1MDcxODI0MDJaFw0zODA1MDgxOTI0MDJaMDExLzAtBgNVBAMTJkdvb2dsZSBDbG91ZCBLZXkgVmF1bHQgU2VydmljZSBSb290IENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArUgzu+4o9yl22eql1BiGBq3gWXooh2ql3J+vVuzf/ThjzdIg0xkkkw/NAFxYFi49Eo1fa/hf8wCIoAqCEs1lD6tE3cCD3T3+EQPquh6CB2KmZDJ6mPnXvVUlUuFr0O2MwZkwylqBETzK0x5NCHgL/p47vkjhHx6LqVaobigKlHxszvVi4fkt/qq7KW3YTVxhwdLGEab+OqSfwMxdBLhMfE0K0dvFt8bs8yJAF04DJsMbRChFFBpT17Z0u53iIAAu5qVQhKrQXiIAwgboZqd+JkHLXU1fJeVT5WJOJgoJFWHkdWkHta4mSYlS72J1Q927JD1JdET1kFtH+EDtYAtx7x7F9xAAbb2tMITws/wwd2rAzZTX/kxRbDlXVLToU05LFYPr+dFV1wvXmi0jlkIxnhdaVBqWC93p528UiUcLpib+HVzMWGdYI3G1NOa/lTp0c8LcbJjapiiVneRQJ3cIqDPOSEnEq40hyZd1jx3JnOxJMwHs8v4s9GIlb3BcOmDvA/Mu09xEMKwpHBm4TFDKXeGHOWha7ccWEECbyO5ncu6XuN2iyz9S+TuMyjZBE552p6Pu5gEC2xk+qab0NGDTHdLKLbyWn3IxdmBHyTr7iPCqmpyHngkC/pbGfvGusc5BpBugsBtlz67m4RWLJ72yAeVPO/ly/8w4orNsGWjn3s0CAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAGiWlu+4qyxgPb6RsA0mwR7V21UJ9rEpYhSN+ARpTWGiI22RCJSGK0ZrPGeFQzE2BpnVRdmLTV5jf9JUStjHoPvNYFnwLTJ0E2e9Olj8MrHrAucAUFLhl4woWz0kU/X0EB1j6Y2SXrAaZPiMMpq8BKj3mH1MbV4stZ0kiHUpZu6PEmrojYG7FKKN30na2xXfiOfl2JusVsyHDqmUn/HjTh6zASKqE6hxE+FJRl2VQ4dcr4SviHtdbimMy2LghLnZ4FE4XhJgRnw9TeRV5C9Sn7pmnAA5X0C8ZXhXvfvrdx4fL3UKlk1Lqlb5skxoK1R9wwr+aNIO+cuR8JA5DmEDWFw5Budh/uWWZlBTyVW2ybbTB6tkmOc8c08XOgxBaKrsXALmJcluabjmN1jp81ae1epeN31jJ4N5IE5aq7XbTFmKkwpgTTvJmqCR2XzWujlvdbdjfiABliWsnLzLQCP8eZwcM4LA5UK3f1ktHolr1OI9etSOkebE2py8LPYBJWlX36tRAagZhU/NoyOtvhRzq9rb3rbf96APEHKUFsXG9nBEd2BUKZghLKPf+JNCU/2pOGx0jdMcf+K+a1DeG0YzGYMRkFvpN3hvHYrJdByL3kSP3UtD0H2g8Ps7gRLELG2HODxbSn8PV3XtuSvxVanA6uyaaS3AZ6SxeVLvmw507aYI"
    //Italian Public Key:
    println("Do you want to use the Italian Public Key? (yes/no)")
    var asw = readLine().toString()
    if(asw=="yes" || asw=="y" || asw=="si"){
        pubkey = "MIIEDzCCAfegAwIBAgIURldu5rsfrDeZtDBxrJ+SujMr2IswDQYJKoZIhvcNAQELBQAwSTELMAkGA1UEBhMCSVQxHzAdBgNVBAoMFk1pbmlzdGVybyBkZWxsYSBTYWx1dGUxGTAXBgNVBAMMEEl0YWx5IERHQyBDU0NBIDEwHhcNMjEwNTEyMDgxODE3WhcNMjMwNTEyMDgxMTU5WjBIMQswCQYDVQQGEwJJVDEfMB0GA1UECgwWTWluaXN0ZXJvIGRlbGxhIFNhbHV0ZTEYMBYGA1UEAwwPSXRhbHkgREdDIERTQyAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnL9+WnIp9fvbcocZSGUFlSw9ffW/jbMONzcvm1X4c+pXOPEs7C4/83+PxS8Swea2hgm/tKt4PI0z8wgnIehoj6OBujCBtzAfBgNVHSMEGDAWgBS+VOVpXmeSQImXYEEAB/pLRVCw/zBlBgNVHR8EXjBcMFqgWKBWhlRsZGFwOi8vY2Fkcy5kZ2MuZ292Lml0L0NOPUl0YWx5JTIwREdDJTIwQ1NDQSUyMHhcMSxPPU1pbmlzdGVybyUyMGRlbGxhJTIwU2FsdXRlLEM9SVQwHQYDVR0OBBYEFC4bAbCvpArrgZ0E+RrqS8V7TNNIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAjxTeF7yhKz/3PKZ9+WfgZPaIzZvnO/nmuUartgVd3xuTPNtd5tuYRNS/1B78HNNk7fXiq5hH2q8xHF9yxYxExov2qFrfUMD5HOZzYKHZcjcWFNHvH6jx7qDCtb5PrOgSK5QUQzycR7MgWIFinoWwsWIrA1AJOwfUoi7v1aoWNMK1eHZmR3Y9LQ84qeE2yDk3jqEGjlJVCbgBp7O8emzy2KhWv3JyRZgTmFz7p6eRXDzUYHtJaufveIhkNM/U8p3S7egQegliIFMmufvEyZemD2BMvb97H9PQpuzeMwB8zcFbuZmNl42AFMQ2PhQe27pU0wFsDEqLe0ETb5eR3T9L6zdSrWldw6UuXoYV0/5fvjA55qCjAaLJ0qi16Ca/jt6iKuws/KKh9yr+FqZMnZUH2D2j2i8LBA67Ie0JoZPSojr8cwSTxQBdJFI722uczCj/Rt69Y4sLdV3hNQ2A9hHrXesyQslr0ez3UHHzDRFMVlOXWCayj3LIgvtfTjKrT1J+/3Vu9fvs1+CCJELuC9gtVLxMsdRc/A6/bvW4mAsyY78ROX27Bi8CxPN5IZbtiyjpmdfr2bufDcwhwzdwsdQQDoSiIF1LZqCn7sHBmUhzoPcBJdXFET58EKow0BWcerZzpvsVHcMTE2uuAUr/JUh1SBpoJCiMIRSl+XPoEA2qqYU="
    }else{
        asw="n"
        println("Do you want to insert a custom Public Key in X.509 cert form? (yes/no)")
        asw = readLine().toString()
        if(asw=="yes" || asw=="y" || asw=="si"){
            println("Use an X.509 certificate containing the Public Key as PEM string: ")
            pubkey = readLine().toString()
        }
    }
    if(verify(inpt, pubkey)){
        println("Valid Key")
    }else{
        println("MISMATCH: Key not valid")
    }

    //BEGINNING MODIFY SECTION DATA
    //IMPORTANT NOTE: To make this section working go in the class CoseData.kt and change val to var for both kid and cbor
    //IMPORTANT: Change in class GreenCertificate.kt and in class Person.kt each val in var

    asw="n"
    println("Do you want to create a new certificate? (y/n)")
    asw = readLine().toString()
    if(asw=="yes" || asw=="y" || asw=="si") {
        //Security.addProvider(BouncyCastleProvider())
        var rm: SecureRandom = SecureRandom.getInstance("SHA1PRNG","SUN")
        var keySize = ECGenParameterSpec("secp256r1")
        var keyGen: KeyPairGenerator = KeyPairGenerator.getInstance("EC","SunEC")//("ECDSA","BC")
        keyGen.initialize(keySize,rm) //It's 256 bit lenght
        var fattoria: KeyFactory = KeyFactory.getInstance("EC","SunEC")//("ECDSA","BC")
        var chiavi = keyGen.generateKeyPair()
        var priv: PrivateKey = chiavi.private
        //var chiavePubblica: PublicKey = chiavi.public
        //var privByteA: ByteArray = byteArrayOf(48,-127,-109,2,1,0,48,19,6,7,42,-122,72,-50,61,2,1,6,8,42,-122,72,-50,61,3,1,7,4,121,48,119,2,1,1,4,32,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,-96,10,6,8,42,-122,72,-50,61,3,1,7,-95,68,3,66,0,4,-100,-65,126,90,114,41,-11,-5,-37,114,-121,25,72,101,5,-107,44,61,125,-11,-65,-115,-77,14,55,55,47,-101,85,-8,115,-22,87,56,-15,44,-20,46,63,-13,127,-113,-59,47,18,-63,-26,-74,-122,9,-65,-76,-85,120,60,-115,51,-13,8,39,33,-24,104,-113)//Wrong provider bouncy castle, the app use SunEC
        //var privByteA: ByteArray = byteArrayOf(48,-127,-109,2,1,0,48,19,6,7,42,-122,72,-50,61,2,1,6,8,42,-122,72,-50,61,3,1,7,4,121,48,119,2,1,1,4,32,52,-102,66,-80,-62,-48,114,-114,105,37,-73,38,13,24,19,-19,-78,113,-59,68,10,-96,-11,60,127,-35,-94,-2,-88,-105,105,-69,-96,10,6,8,42,-122,72,-50,61,3,1,7,-95,68,3,66,0,4,-100,-65,126,90,114,41,-11,-5,-37,114,-121,25,72,101,5,-107,44,61,125,-11,-65,-115,-77,14,55,55,47,-101,85,-8,115,-22,87,56,-15,44,-20,46,63,-13,127,-113,-59,47,18,-63,-26,-74,-122,9,-65,-76,-85,120,60,-115,51,-13,8,39,33,-24,104,-113)//HERE HAS BEEN INSERTED A POSSIBLE PRIVATE ITALIAN KEY
        var privByteA: MutableList<Byte> = byteArrayOf(48,65,2,1,0,48,19,6,7,42,-122,72,-50,61,2,1,6,8,42,-122,72,-50,61,3,1,7,4,39,48,37,2,1,1,4,32,52,-102,66,-80,-62,-48,114,-114,105,37,-73,38,13,24,19,-19,-78,113,-59,68,10,-96,-11,60,127,-35,-94,-2,-88,-105,105,-69).toMutableList() //This private key example respect SunEC provider structure
        //What internet think could be the private Italian key: 52,-102,66,-80,-62,-48,114,-114,105,37,-73,38,13,24,19,-19,-78,113,-59,68,10,-96,-11,60,127,-35,-94,-2,-88,-105,105,-69 but seems not true.
        //var privByteA: ByteArray = byteArrayOf(48,-127,-109,2,1,0,48,19,6,7,42,-122,72,-50,61,2,1,6,8,42,-122,72,-50,61,3,1,7,4,121,48,119,2,1,1,4,32,-65,55,16,63,74,15,-110,76,80,-102,115,58,-119,31,-101,61,-3,-2,82,6,85,-8,55,33,10,104,101,85,62,45,110,41,-96,10,6,8,42,-122,72,-50,61,3,1,7,-95,68,3,66,0,4,-100,-65,126,90,114,41,-11,-5,-37,114,-121,25,72,101,5,-107,44,61,125,-11,-65,-115,-77,14,55,55,47,-101,85,-8,115,-22,87,56,-15,44,-20,46,63,-13,127,-113,-59,47,18,-63,-26,-74,-122,9,-65,-76,-85,120,60,-115,51,-13,8,39,33,-24,104,-113)//BouncyCastle structure private key Wrong
        asw="n"
        println("Do you want to insert a Private Key? (y/n)")
        asw = readLine().toString()
        if(asw=="yes" || asw=="y" || asw=="si") {
            try {
                println("Use a PKCS8 key in PEM format: ")
                var tmpPBK = readLine().toString().replace("\n","")
                privByteA = byteArrayOf(0).toMutableList()
                var partialKey = Base64.getDecoder().decode(tmpPBK)
                var c=0
                for (b in partialKey) {
                    privByteA.add(c, b)
                    c++
                }
            }catch(e: Exception){
                println("\nErrore in Private Key: $e \n")
            }
        }
        var specPriv: EncodedKeySpec = PKCS8EncodedKeySpec(privByteA.toByteArray())
        //var specPriv: PKCS8EncodedKeySpec = PKCS8EncodedKeySpec(Base64.getDecoder().decode("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZgp3uylFeCIIXozbZkCkSNr4DcLDxplZ1ax/u7ndXqahRANCAARkJeqyO85dyR+UrQ5Ey8EdgLyf9NtsCrwORAj6T68/elL19aoISQDbzaNYJjdD77XdHtd+nFGTQVpB88wPTwgb"))

        try{
            priv = fattoria.generatePrivate(specPriv)
        }catch (e: Exception){
            println("\nErrore in fattoria: $e \n")
        }

        asw="n"
        println("Do you want to change the Public Key? (y/n)")
        asw = readLine().toString()
        if(asw=="yes" || asw=="y" || asw=="si"){
            println("Use an X.509 certificate containing the Public Key as PEM string: ")
            pubkey = readLine().toString().replace("\n","")
        }

        var map = CBORObject.DecodeFromBytes(coseStructured.cbor) //map: {4: 1683880017, 6: 1622973252, 1: "GR", -260: {1: {"t": [{"sc"....
        var hcert = map[CwtHeaderKeys.HCERT.asCBOR()] //hcert: {1: {"t": [{"sc"...
        var orCBO = hcert[CBORObject.FromObject(1)] //orCBO: {"t": [{"sc"...
        var tmpSr = orCBO.toString()
        println("What is the name in the original certificate? ")
        var name = readLine().toString().uppercase()
        println("What is the new name you want to insert in the certificate? ")
        var new_name = readLine().toString().uppercase()
        println("What is the SURname in the original certificate? ")
        var surname = readLine().toString().uppercase()
        println("What is the new SURname you want to insert in the certificate? ")
        var new_surname = readLine().toString().uppercase()
        println("What is the original born date inside the certificate? (YYYY-MM-DD) ")
        var date = readLine().toString()
        println("What is the date you want to insert in the certificate? (YYYY-MM-DD)")
        var new_date = readLine().toString()
        tmpSr = tmpSr.replace(name, new_name)
        tmpSr = tmpSr.replace(surname, new_surname)
        tmpSr = tmpSr.replace(date, new_date) //YYYY-MM-DD
        var cbo = CBORObject.FromJSONString(tmpSr)
        hcert[CBORObject.FromObject(1)] = cbo
        map[CwtHeaderKeys.HCERT.asCBOR()] = hcert
        coseStructured.cbor = map.EncodeToBytes()

        //END MODIFY SECTION
        //Encoding
        //cosecborsr is the equivalent to the decompressed archive
        var cosecborsr = coseStructured.encodeCose(cosecborstring) //Note: zlibArchive here is only to chose where to locate some bytes
        var msgObj = CBORObject.DecodeFromBytes(cosecborstring)
        var msgObj2 = CBORObject.DecodeFromBytes(cosecborsr) //So I take the changed content
        val protected = msgObj[0].GetByteString()
        var dsa: Signature = Signature.getInstance(VerificationCryptoService.Algo.ALGO_ECDSA256.value)
        var dataToBeSigned = CBORObject.NewArray().apply {
            Add("Signature1")
            Add(protected)
            Add(ByteArray(0))
            Add(msgObj2[2].GetByteString())
        }.EncodeToBytes()
        val certa: X509Certificate = toCertificate(pubkey)
        dsa.initSign(priv) //Needs a Private Key where can I get it?!
        dsa.update(dataToBeSigned)
        var firmaMia: ByteArray = dsa.sign()
        var firmaDER = convToDer(firmaMia)
        msgObj2[3] = CBORObject.FromObject(firmaDER) //The sign is in this format, the 88 and 64 appear afert extracting the signature with EncodeToBytes()    
        var compressed = msgObj2.EncodeToBytes().compressBase45DecodedData() //Getting the ZlibArchive - Works Tested
        var noprefix = compressed.encodeBase45() //Getting the BD45 without prefix - Works Tested
        var withprefix = dfv.encode(noprefix) //Tested it works
        println(withprefix) // BE AWARE TO INVISIBLE CHARACTERS AT THE END OF THE STRING LIKE SPACE OR LINE RETURN
        readableGreenPass = coseStructured.cbor.decodeGreenCertificate()
        println(readableGreenPass)

        if (verify(withprefix, pubkey)) {
            println("Valid Key")
        } else {
            println("MISMATCH: Key not valid")
        }
        println("Used private: ${Base64.getEncoder().encodeToString(priv.encoded)}")
        println("Used public: $pubkey")
    }else{
        println("Thank you to have used the program!")
    }
}