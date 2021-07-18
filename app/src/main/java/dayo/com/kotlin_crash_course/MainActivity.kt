package dayo.com.kotlin_crash_course

import android.os.Bundle
import android.view.View
import android.widget.*
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import dayo.com.kotlin_crash_course.BlackBoxLogicClass.BlackBoxLogic
import dayo.com.kotlin_crash_course.BlackBoxLogicClass.byteArrayToHexString
import dayo.com.kotlin_crash_course.BlackBoxLogicClass.hexStringToByteArray
import dayo.com.kotlin_crash_course.Constants.productionValue
import dayo.com.kotlin_crash_course.XORorAndorORClass.XORorANDorORfunction
import org.w3c.dom.Text
import java.io.ByteArrayOutputStream
import java.security.spec.KeySpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.DESKeySpec


class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)


        var ipekValue = findViewById<EditText>(R.id.ipekValue)
        var ksnValue = findViewById<EditText>(R.id.ksnValue)

        val switchButton = findViewById<Switch>(R.id.switchKeys)
        val switchText = findViewById<TextView>(R.id.switchTexts)
        switchButton.setOnCheckedChangeListener { compoundButton, _ ->

            if(compoundButton.isChecked) {
                switchText.setText(productionValue).toString()
                ipekValue.setText(Constants.productionIpek).toString()
                ksnValue.setText(Constants.productionKsn).toString()
            }
            else{
                switchText.setText(Constants.testValue).toString()
                ipekValue.setText(Constants.testIpek).toString()
                ksnValue.setText(Constants.testKsn).toString()
            }
        }

        val workingKeyButton = findViewById<Button>(R.id.workingKeyBut)
        workingKeyButton.setOnClickListener{
            workingKeyFunction();
        }

//        val pinBlock = DesEncryptDukpt(
//            workingKey = getSessionKey(),
//            pan = "5399419000144402",
//            clearPin = "4562"
//        )
//        println("****************The expected value of the pinblock is: $pinBlock")
        //Production IPEK: 3F2216D8297BCE9C Production KSN: 0000000002DDDDE00000
        //Test IPEK: 9F8011E7E71E483B KSN: 0000000006DDDDE01500
    }

    private fun workingKeyFunction() {
        var ipekValue = findViewById<EditText>(R.id.ipekValue)
        var ksnValue = findViewById<EditText>(R.id.ksnValue)
        if (ksnValue.length() != 20)
            Toast.makeText(this, "KSN must be 10bytes", Toast.LENGTH_SHORT).show()
        if (ipekValue.length() == 16 || ipekValue.length() == 32) {
            val ksnCounterValue = findViewById<EditText>(R.id.ksnCountValue)
            if (ksnCounterValue.getText().toString().isEmpty()) {
                Toast.makeText(this,"KSN Counter cannot be empty", Toast.LENGTH_SHORT).show()
            }
            val ksnLength = ksnValue.getText().toString().length
            val ksnCounterLength = ksnCounterValue.length()
            println("The expected value of the ksn counter length is $ksnCounterLength")
            val neededValue = ksnLength - ksnCounterLength
            val ksnNewValue = ksnValue.getText().substring(0, neededValue) + ksnCounterValue.getText().toString()
            println("The expected value of the new addition KSN value is $ksnNewValue")
            var ksnValue = ksnNewValue
            getSessionKey(
                IPEK = ipekValue.getText().toString(),
                KSN = ksnValue
            )
        }
        else{
            Toast.makeText(this, "IPEK must either be 8bytes or 16bytes", Toast.LENGTH_SHORT).show()
        }
    }


    fun getSessionKey(IPEK: String, KSN: String): String {
        var initialIPEK: String = IPEK
        println("The expected value of the initial IPEK $initialIPEK")
        val ksn = KSN.padStart(20, '0')
        println("The expected value of the ksn $ksn")
        var sessionkey = ""
        //Get ksn with a zero counter by ANDing it with 0000FFFFFFFFFFE00000
        val newKSN = XORorANDorORfunction(ksn, "0000FFFFFFFFFFE00000", "&")
        println("The expected value of the new KSN is $newKSN")
        val counterKSN = ksn.substring(ksn.length - 5).padStart(16, '0')
        println("The expected value of the counter KSN is $counterKSN")
        //get the number of binary associated with the counterKSN number
        var newKSNtoleft16 = newKSN.substring(newKSN.length - 16)
        println("The expected value of the new KSN to left 16 $newKSNtoleft16")
        val counterKSNbin = Integer.toBinaryString(counterKSN.toInt())
        println("The expected value of the counter KSN Bin $counterKSNbin")
        var binarycount = counterKSNbin
        for (i in 0 until counterKSNbin.length) {
            val len: Int = binarycount.length
            var result = ""
            if (binarycount.substring(0, 1) == "1") {
                result = "1".padEnd(len, '0')
                println("The expected value of the result is $result")
                binarycount = binarycount.substring(1)
                println("The expected value of the new binary count is $binarycount")
            } else {
                binarycount = binarycount.substring(1)
                println("The expected value of the new binary count is $binarycount")
                continue
            }
            val counterKSN2 = Integer.toHexString(Integer.parseInt(result, 2))
                .toUpperCase().padStart(16, '0')
            println("The expected value of the counter ksn 2 is $counterKSN2")
            val newKSN2 = XORorANDorORfunction(newKSNtoleft16, counterKSN2, "|")
            println("The expected value of the new ksn 2 is $newKSN2")
            sessionkey = BlackBoxLogic(newKSN2, initialIPEK) //Call the Black Box from here
            println("The expected value of the session key here is $sessionkey")
            newKSNtoleft16 = newKSN2
            initialIPEK = sessionkey
        }
        val checkWorkingKey = XORorANDorORfunction(
            sessionkey,
            "00000000000000FF00000000000000FF",
            "^"
        )
        val workingKeyValue = findViewById<EditText>(R.id.workingKeyValue)
        workingKeyValue.setText(checkWorkingKey)
        println("*************************The expected value of the working key is $checkWorkingKey")
        return XORorAndorORClass.XORorANDorORfunction(sessionkey, "00000000000000FF00000000000000FF", "^")
    }

    fun encryptPinBlock(pan: String, pin: String): String {
        val pan = pan.substring(pan.length - 13).take(12).padStart(16, '0')
        println("The expected value of the encrypted pan is $pan")
        val pin = '0' + pin.length.toString(16) + pin.padEnd(16, 'F')
        println("The expected value of the clear pin is $pin")
        return XORorANDorORfunction(pan, pin, "^") //the clear pinblock is returned here
    }

    fun DesEncryptDukpt(workingKey: String, pan: String, clearPin: String): String {
        val pinBlock = XORorANDorORfunction(workingKey, encryptPinBlock(pan, clearPin), "^")
        val keyData = hexStringToByteArray(workingKey)
        val bout = ByteArrayOutputStream()
        try {
            val keySpec: KeySpec = DESKeySpec(keyData)
            val key: SecretKey = SecretKeyFactory.getInstance("DES").generateSecret(keySpec)
            val cipher: Cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            bout.write(cipher.doFinal(hexStringToByteArray(pinBlock)))
        } catch (e: Exception) {
            println("Exception .. " + e.message)
        }
        return XORorANDorORfunction(
            workingKey, byteArrayToHexString(bout.toByteArray()).substring(
                0,
                16
            ), "^"
        )
    }

}