package com.passaura.os.policy

import android.content.ComponentName

interface DevicePolicyManagerWrapper {
    fun isDeviceOwnerApp(packageName: String): Boolean
    /** Credential manager allowlist (DevicePolicyManager.setCredentialManagerPolicy, API 34+). */
    fun setCredentialManagerAllowlist(admin: ComponentName, packages: Set<String>)
    fun addUserRestriction(admin: ComponentName, restriction: String)
}
