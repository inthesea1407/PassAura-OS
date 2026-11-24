package com.passaura.os.policy

import android.app.admin.DevicePolicyManager
import android.content.ComponentName

class RealDevicePolicyManagerWrapper(private val dpm: DevicePolicyManager) : DevicePolicyManagerWrapper {
    override fun isDeviceOwnerApp(packageName: String): Boolean = dpm.isDeviceOwnerApp(packageName)
    
    override fun setPermittedAutofillService(admin: ComponentName, packageName: String?) {
        dpm.setPermittedAutofillService(admin, packageName)
    }
    
    override fun addUserRestriction(admin: ComponentName, restriction: String) {
        dpm.addUserRestriction(admin, restriction)
    }
}
