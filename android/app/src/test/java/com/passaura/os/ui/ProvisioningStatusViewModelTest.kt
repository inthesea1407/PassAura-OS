package com.passaura.os.ui

import android.content.ComponentName
import android.content.Context
import android.content.SharedPreferences
import com.passaura.os.util.AppPreferences
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class ProvisioningStatusViewModelTest {

    private lateinit var fakeDpm: FakeDevicePolicyManagerWrapper
    private lateinit var prefs: AppPreferences
    private lateinit var adminComponent: ComponentName
    private var fakeClockValue: Long = 1_700_000_000_000L

    @Before
    fun setup() {
        fakeDpm = FakeDevicePolicyManagerWrapper()
        adminComponent = ComponentName("com.passaura.os", "com.passaura.os.admin.PassAuraDeviceAdminReceiver")

        val sharedPrefs: SharedPreferences = mockk(relaxed = true)
        every { sharedPrefs.getString("device_id", null) } returns null
        every { sharedPrefs.getString("premium_until", null) } returns null
        every { sharedPrefs.edit() } returns mockk(relaxed = true)

        val context: Context = mockk(relaxed = true)
        every { context.getSharedPreferences("passaura_prefs", Context.MODE_PRIVATE) } returns sharedPrefs

        prefs = AppPreferences(context)
    }

    private fun newViewModel(): ProvisioningStatusViewModel =
        ProvisioningStatusViewModel(fakeDpm, adminComponent, prefs) { fakeClockValue }

    @Test
    fun `initial status is null before refresh`() {
        val vm = newViewModel()
        assertNull(vm.status.value)
    }

    @Test
    fun `refresh reports not device owner and not registered when empty`() {
        fakeDpm.isDeviceOwnerResult = false
        val vm = newViewModel()

        vm.refresh()

        val s = vm.status.value
        assertNotNull(s)
        assertFalse(s!!.isDeviceOwner)
        assertFalse(s.isRegistered)
        assertNull(s.deviceId)
        assertNull(s.premiumUntil)
        assertEquals(fakeClockValue, s.lastCheckTimeMillis)
    }

    @Test
    fun `refresh reports device owner true when wrapper says true`() {
        fakeDpm.isDeviceOwnerResult = true
        val vm = newViewModel()

        vm.refresh()

        assertTrue(vm.status.value!!.isDeviceOwner)
    }

    @Test
    fun `refresh reflects registered state and device id from preferences`() {
        // Simulate a registered device by writing through prefs
        val sharedPrefs: SharedPreferences = mockk(relaxed = true)
        every { sharedPrefs.getString("device_id", null) } returns "device-uuid-123"
        every { sharedPrefs.getString("premium_until", null) } returns "2027-01-01T00:00:00Z"
        every { sharedPrefs.edit() } returns mockk(relaxed = true)

        val context: Context = mockk(relaxed = true)
        every { context.getSharedPreferences("passaura_prefs", Context.MODE_PRIVATE) } returns sharedPrefs
        val registeredPrefs = AppPreferences(context)

        val vm = ProvisioningStatusViewModel(fakeDpm, adminComponent, registeredPrefs) { fakeClockValue }
        vm.refresh()

        val s = vm.status.value!!
        assertTrue(s.isRegistered)
        assertEquals("device-uuid-123", s.deviceId)
        assertEquals("2027-01-01T00:00:00Z", s.premiumUntil)
    }

    @Test
    fun `refresh uses clock for lastCheckTimeMillis`() {
        val vm = newViewModel()
        fakeClockValue = 1_700_000_001_000L
        vm.refresh()
        assertEquals(1_700_000_001_000L, vm.status.value!!.lastCheckTimeMillis)

        fakeClockValue = 1_700_000_002_000L
        vm.refresh()
        assertEquals(1_700_000_002_000L, vm.status.value!!.lastCheckTimeMillis)
    }
}
