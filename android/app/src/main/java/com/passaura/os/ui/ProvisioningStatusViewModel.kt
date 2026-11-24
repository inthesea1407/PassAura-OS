package com.passaura.os.ui

import android.content.ComponentName
import com.passaura.os.policy.DevicePolicyManagerWrapper
import com.passaura.os.util.AppPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

class ProvisioningStatusViewModel(
    private val dpmWrapper: DevicePolicyManagerWrapper,
    private val adminComponent: ComponentName,
    private val prefs: AppPreferences,
    private val clock: () -> Long = { System.currentTimeMillis() }
) {
    data class Status(
        val isDeviceOwner: Boolean,
        val isRegistered: Boolean,
        val deviceId: String?,
        val premiumUntil: String?,
        val lastCheckTimeMillis: Long
    )

    private val _status = MutableStateFlow<Status?>(null)
    val status: StateFlow<Status?> = _status.asStateFlow()

    fun refresh() {
        _status.value = Status(
            isDeviceOwner = dpmWrapper.isDeviceOwnerApp(adminComponent.packageName),
            isRegistered = prefs.isRegistered,
            deviceId = prefs.deviceId,
            premiumUntil = prefs.premiumUntil,
            lastCheckTimeMillis = clock()
        )
    }
}
