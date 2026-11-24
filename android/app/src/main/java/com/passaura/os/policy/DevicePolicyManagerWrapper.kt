package com.passaura.os.policy

import android.content.ComponentName

interface DevicePolicyManagerWrapper {
    fun isDeviceOwnerApp(packageName: String): Boolean
    fun setPermittedAutofillService(admin: ComponentName, packageName: String?)
    fun addUserRestriction(admin: ComponentName, restriction: String)
}
