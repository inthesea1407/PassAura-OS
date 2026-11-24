package com.passaura.os.ui

import android.content.ComponentName
import com.passaura.os.policy.DevicePolicyManagerWrapper

class FakeDevicePolicyManagerWrapper : DevicePolicyManagerWrapper {
    var isDeviceOwnerResult: Boolean = false
    val allowlistCalls: MutableList<Pair<ComponentName, Set<String>>> = mutableListOf()
    val addUserRestrictionCalls: MutableList<Pair<ComponentName, String>> = mutableListOf()

    override fun isDeviceOwnerApp(packageName: String): Boolean = isDeviceOwnerResult

    override fun setCredentialManagerAllowlist(admin: ComponentName, packages: Set<String>) {
        allowlistCalls.add(admin to packages)
    }

    override fun addUserRestriction(admin: ComponentName, restriction: String) {
        addUserRestrictionCalls.add(admin to restriction)
    }
}
