package com.passaura.os.ui

import android.content.ComponentName
import com.passaura.os.policy.DevicePolicyManagerWrapper

class FakeDevicePolicyManagerWrapper : DevicePolicyManagerWrapper {
    var isDeviceOwnerResult: Boolean = false
    val setAutofillCalls: MutableList<Pair<ComponentName, String?>> = mutableListOf()
    val addUserRestrictionCalls: MutableList<Pair<ComponentName, String>> = mutableListOf()

    override fun isDeviceOwnerApp(packageName: String): Boolean = isDeviceOwnerResult

    override fun setPermittedAutofillService(admin: ComponentName, packageName: String?) {
        setAutofillCalls.add(admin to packageName)
    }

    override fun addUserRestriction(admin: ComponentName, restriction: String) {
        addUserRestrictionCalls.add(admin to restriction)
    }
}
