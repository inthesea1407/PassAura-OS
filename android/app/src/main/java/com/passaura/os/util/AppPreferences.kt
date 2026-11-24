package com.passaura.os.util

import android.content.Context
import android.content.SharedPreferences

class AppPreferences(context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences("passaura_prefs", Context.MODE_PRIVATE)

    var deviceId: String?
        get() = prefs.getString("device_id", null)
        set(value) = prefs.edit().putString("device_id", value).apply()

    var premiumUntil: String?
        get() = prefs.getString("premium_until", null)
        set(value) = prefs.edit().putString("premium_until", value).apply()
        
    var isRegistered: Boolean
        get() = deviceId != null
        set(value) = if (!value) prefs.edit().remove("device_id").remove("premium_until").apply() else Unit
}
