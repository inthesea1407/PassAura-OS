package com.passaura.os.policy

import android.app.admin.DevicePolicyManager
import android.app.admin.PackagePolicy
import android.content.ComponentName
import android.os.Build

class RealDevicePolicyManagerWrapper(private val dpm: DevicePolicyManager) : DevicePolicyManagerWrapper {
    override fun isDeviceOwnerApp(packageName: String): Boolean = dpm.isDeviceOwnerApp(packageName)

    override fun setCredentialManagerAllowlist(admin: ComponentName, packages: Set<String>) {
        check(Build.VERSION.SDK_INT >= 34) { "Credential manager policy needs Android 14 (API 34) or newer" }
        dpm.setCredentialManagerPolicy(PackagePolicy(PackagePolicy.PACKAGE_POLICY_ALLOWLIST, packages))
    }

    override fun addUserRestriction(admin: ComponentName, restriction: String) {
        dpm.addUserRestriction(admin, restriction)
    }
}
