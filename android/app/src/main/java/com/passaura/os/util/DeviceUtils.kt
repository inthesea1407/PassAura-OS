kotlin
package com.passaura.os.util

import android.content.Context
import com.passaura.os.BuildConfig
import android.provider.Settings
import java.security.MessageDigest

object DeviceUtils {
    /**
     * Generates a 64 lowercase hex char SHA-256 hash of the salted hardware ID.
     * The raw ID never leaves the device, per CONTRACTS.md.
     */
    fun getHardwareIdHash(context: Context): String {
        val androidId = Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID) ?: "unknown"
        val salt = BuildConfig.HW_ID_SALT  // domain separation, not a secret; set via -PposHwSalt
        val raw = androidId + salt
        val bytes = MessageDigest.getInstance("SHA-256").digest(raw.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
