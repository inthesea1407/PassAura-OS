package com.passaura.os.policy

import android.content.ComponentName
import android.os.UserManager
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.Before
import org.junit.Test

class PolicyEnforcerTest {
    private lateinit var dpmWrapper: DevicePolicyManagerWrapper
    private lateinit var enforcer: PolicyEnforcer
    
    private val adminComponent = mockk<ComponentName>(relaxed = true)
    private val premiumPackage = "com.passaura.premium"

    @Before
    fun setup() {
        dpmWrapper = mockk(relaxed = true)
        every { adminComponent.packageName } returns "com.passaura.os"
        enforcer = PolicyEnforcer(dpmWrapper, adminComponent, premiumPackage)
    }

    @Test
    fun `enforcePassAuraOnly sets credential manager allowlist and checks device owner`() {
        every { dpmWrapper.isDeviceOwnerApp("com.passaura.os") } returns true

        enforcer.enforcePassAuraOnly()

        verify { dpmWrapper.isDeviceOwnerApp("com.passaura.os") }
        verify { dpmWrapper.setCredentialManagerAllowlist(adminComponent, setOf(premiumPackage)) }
        verify { dpmWrapper.addUserRestriction(adminComponent, UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES) }
        verify { dpmWrapper.addUserRestriction(adminComponent, UserManager.DISALLOW_ADD_USER) }
    }

    @Test(expected = IllegalStateException::class)
    fun `enforcePassAuraOnly throws if not device owner`() {
        every { dpmWrapper.isDeviceOwnerApp("com.passaura.os") } returns false
        enforcer.enforcePassAuraOnly()
    }
}
