package dayo.com.kotlin_crash_course

import java.io.ByteArrayOutputStream
import java.security.spec.KeySpec
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.DESKeySpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object BlackBoxLogicClass {


    fun BlackBoxLogic(ksn: String, iPek: String): String {
        if (iPek.length < 32) {
            println("The expected value IPEK $iPek and IKSN is $ksn")
            val msg = XORorAndorORClass.XORorANDorORfunction(iPek, ksn, "^")
            println("The expected value of the msg is $msg")
            val desreslt = desEncrypt(msg, iPek)
            println("The expected value of the desresult is $desreslt")
            val rsesskey = XORorAndorORClass.XORorANDorORfunction(desreslt, iPek, "^")
            println("The expected value of the session key during BBL is $rsesskey")
            return rsesskey
        }
        val current_sk = iPek
        val ksn_mod = ksn
        val leftIpek =
            XORorAndorORClass.XORorANDorORfunction(
                current_sk,
                "FFFFFFFFFFFFFFFF0000000000000000",
                "&"
            ).substring(16)
        val rightIpek =
            XORorAndorORClass.XORorANDorORfunction(
                current_sk,
                "0000000000000000FFFFFFFFFFFFFFFF",
                "&"
            ).substring(16)
        val message = XORorAndorORClass.XORorANDorORfunction(rightIpek, ksn_mod, "^")
        val desresult = desEncrypt(message, leftIpek)
        val rightSessionKey = XORorAndorORClass.XORorANDorORfunction(desresult, rightIpek, "^")
        val resultCurrent_sk =
            XORorAndorORClass.XORorANDorORfunction(
                current_sk,
                "C0C0C0C000000000C0C0C0C000000000",
                "^"
            )
        val leftIpek2 = XORorAndorORClass.XORorANDorORfunction(
            resultCurrent_sk,
            "FFFFFFFFFFFFFFFF0000000000000000",
            "&"
        ).substring(0, 16)
        val rightIpek2 = XORorAndorORClass.XORorANDorORfunction(
            resultCurrent_sk,
            "0000000000000000FFFFFFFFFFFFFFFF",
            "&"
        ).substring(16)
        val message2 = XORorAndorORClass.XORorANDorORfunction(rightIpek2, ksn_mod, "^")
        val desresult2 = desEncrypt(message2, leftIpek2)
        val leftSessionKey = XORorAndorORClass.XORorANDorORfunction(desresult2, rightIpek2, "^")
        return leftSessionKey + rightSessionKey
    }

    private fun desEncrypt(desData: String, key: String): String {
        val keyData = hexStringToByteArray(key)
        val bout = ByteArrayOutputStream()
        try {
            val keySpec: KeySpec = DESKeySpec(keyData)
            val key: SecretKey = SecretKeyFactory.getInstance("DES").generateSecret(keySpec)
            val cipher: Cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            bout.write(cipher.doFinal(hexStringToByteArray(desData)))
        } catch (e: Exception) {
            print("Exception DES Encryption.. " + e.printStackTrace())
        }
        return byteArrayToHexString(bout.toByteArray()).substring(0, 16)
    }

    fun hexStringToByteArray(key: String) : ByteArray {
        var result:ByteArray = ByteArray(0)
        for (i in key.indices step 2) {
            result += Integer.parseInt(key.substring(i, (i + 2)), 16).toByte()
        }
        return result
    }

    fun byteArrayToHexString(key: ByteArray) : String {
        var st = ""
        for (b in key) {
            st += String.format("%02X", b)
        }
        return st
    }

}