package dayo.com.kotlin_crash_course

import android.os.Build
import android.os.Bundle
import android.widget.*
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import dayo.com.kotlin_crash_course.BlackBoxLogicClass.BlackBoxLogic
import dayo.com.kotlin_crash_course.BlackBoxLogicClass.byteArrayToHexString
import dayo.com.kotlin_crash_course.BlackBoxLogicClass.hexStringToByteArray
import dayo.com.kotlin_crash_course.Constants.productionIpek
import dayo.com.kotlin_crash_course.Constants.productionKsn
import dayo.com.kotlin_crash_course.Constants.productionValue
import dayo.com.kotlin_crash_course.Constants.testIpek
import dayo.com.kotlin_crash_course.Constants.testKsn
import dayo.com.kotlin_crash_course.Constants.testValue
import dayo.com.kotlin_crash_course.XORorAndorORClass.XORorANDorORfunction
import dayo.com.kotlin_crash_course.databinding.ActivityMainBinding
import java.io.ByteArrayOutputStream
import java.security.spec.KeySpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.DESKeySpec


class MainActivity : AppCompatActivity() {
    private var _binding : ActivityMainBinding? = null
    private val binding get() = _binding!!

    @RequiresApi(Build.VERSION_CODES.R)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        //window.decorView.windowInsetsController!!.hide(android.view.WindowInsets.Type.statusBars())
        _binding = ActivityMainBinding.inflate(layoutInflater)
        val view = binding.root
        setContentView(view)
        populateViewBindingTexts()
    }
    private fun populateViewBindingTexts(){
        val ipekValue = binding.ipekValue
        val ksnValue = binding.ksnValue
        val switchButton = binding.switchKeys
        val switchText = binding.switchTexts
        val workingKeyButton = binding.workingKeyBut
        val encryptButton = binding.encryptButton

        switchButton.setOnCheckedChangeListener { compoundButton, _ ->
            if(compoundButton.isChecked) {
                switchText.text = productionValue
                ipekValue.setText(productionIpek).toString()
                ksnValue.setText(productionKsn).toString()
            }
            else{
                switchText.text = testValue
                ipekValue.setText(testIpek).toString()
                ksnValue.setText(testKsn).toString()
            }
        }

        workingKeyButton.setOnClickListener{
            workingKeyFunction();
        }

        encryptButton.setOnClickListener(){
            generatePinblock()
        }
    }
    private fun generatePinblock() {
        val workingKeyVal = binding.workingKeyValue
        val clearPan = binding.clearPan
        val clearPinBlock = binding.clearPin
        if (clearPan.length() < 16 || clearPan.length() > 19){
            Toast.makeText(this, "Pan should be between 16 and 19 digits", Toast.LENGTH_SHORT).show()
        }
        else {
            desEncryptDukpt(
                workingKey = workingKeyVal.text.toString(),
                pan = clearPan.text.toString(),
                clearPin = clearPinBlock.text.toString()
            )
        }
    }

    private fun workingKeyFunction() {
        val ipekValue = binding.ipekValue
        val ksnValue = binding.ksnValue
        if (ksnValue.length() != 20)
            Toast.makeText(this.applicationContext, "KSN must be 10bytes", Toast.LENGTH_SHORT).show()
        if (ipekValue.length() == 16 || ipekValue.length() == 32) {
            val ksnCounterValue = binding.ksnCountValue
            if (ksnCounterValue.text.toString().isEmpty()) {
                Toast.makeText(this.applicationContext,"KSN Counter cannot be empty", Toast.LENGTH_SHORT).show()
            }
            val ksnLength = ksnValue.text.toString().length
            val ksnCounterLength = ksnCounterValue.length()
            println("The expected value of the ksn counter length is $ksnCounterLength")
            val neededValue = ksnLength - ksnCounterLength
            val ksnNewValue = ksnValue.text.substring(0, neededValue) + ksnCounterValue.text.toString()
            println("The expected value of the new addition KSN value is $ksnNewValue")

            getSessionKey(
                IPEK = ipekValue.text.toString(),
                KSN = ksnNewValue
            )
        }
        else{
            Toast.makeText(this, "IPEK must either be 8bytes or 16bytes", Toast.LENGTH_SHORT).show()
        }
    }

    private fun getSessionKey(IPEK: String, KSN: String): String {
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
        for (i in counterKSNbin.indices) {
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
        return XORorANDorORfunction(sessionkey, "00000000000000FF00000000000000FF", "^")
    }

    private fun encryptPinBlock(pan: String, pin: String): String {
        val pan = pan.substring(pan.length - 13).take(12).padStart(16, '0')
        println("The expected value of the encrypted pan is $pan")
        val pin = '0' + pin.length.toString(16) + pin.padEnd(16, 'F')
        println("The expected value of the clear pin is $pin")
        return XORorANDorORfunction(pan, pin, "^") //the clear pinblock is returned here
    }

    private fun desEncryptDukpt(workingKey: String, pan: String, clearPin: String) {
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
        val encryptPin = XORorANDorORfunction(
            workingKey, byteArrayToHexString(bout.toByteArray()).substring(
                0,
                16
            ), "^"
        )
        println("****************The expected value of the pinblock is: $encryptPin")
        val encryptedPinblock = binding.pinBlock
        encryptedPinblock.setText(encryptPin)
    }

    override fun onDestroy() {
        _binding = null
        super.onDestroy()
    }

}