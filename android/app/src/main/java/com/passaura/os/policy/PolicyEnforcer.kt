package com.passaura.os.policy

import android.content.ComponentName
import android.os.UserManager

class PolicyEnforcer(
    private val dpmWrapper: DevicePolicyManagerWrapper,
    private val adminComponent: ComponentName,
    private val premiumPackage: String
) {
    /**
     * Enforces PassAura Premium as the only allowed credential/autofill manager.
     * 
     * HONEST LIMIT (per ARCHITECTURE.md): This is the portable layer (Device Owner API). 
     * It cannot fully block apps that declare no capabilities (e.g., screen scrapers, 
     * browsers with built-in password saving). Full blocking requires the Full ROM layer 
     * (installer hooks, SELinux, accessibility service denial), which is not built yet.
     * 
     * Requires device-owner provisioning via ADB or QR code.
     * setPermittedAutofillService requires API 26+.
     */
    fun enforcePassAuraOnly() {
        if (!dpmWrapper.isDeviceOwnerApp(adminComponent.packageName)) {
            throw IllegalStateException("App is not provisioned as device owner")
        }

        dpmWrapper.setPermittedAutofillService(adminComponent, premiumPackage)
        dpmWrapper.addUserRestriction(adminComponent, UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES)
        dpmWrapper.addUserRestriction(adminComponent, UserManager.DISALLOW_ADD_USER)
    }
}
