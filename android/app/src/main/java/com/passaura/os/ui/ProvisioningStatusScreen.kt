package com.passaura.os.ui

import android.content.ComponentName
import android.text.format.DateFormat
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.passaura.os.R
import com.passaura.os.policy.DevicePolicyManagerWrapper
import com.passaura.os.policy.RealDevicePolicyManagerWrapper
import com.passaura.os.util.AppPreferences
import java.util.Date

@Composable
fun ProvisioningStatusScreen(
    prefs: AppPreferences,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val d_talkback_refresh_button = stringResource(R.string.talkback_refresh_button)
    val dpm = context.getSystemService(android.content.Context.DEVICE_POLICY_SERVICE)
            as android.app.admin.DevicePolicyManager
    val dpmWrapper: DevicePolicyManagerWrapper = remember { RealDevicePolicyManagerWrapper(dpm) }
    val adminComponent = remember {
        ComponentName(context.packageName, "com.passaura.os.admin.PassAuraDeviceAdminReceiver")
    }
    val viewModel = remember { ProvisioningStatusViewModel(dpmWrapper, adminComponent, prefs) }

    LaunchedEffect(Unit) { viewModel.refresh() }

    val status by viewModel.status.collectAsState()

    ProvisioningStatusContent(
        status = status,
        onRefresh = { viewModel.refresh() },
        onBack = onBack
    )
}

@Composable
internal fun ProvisioningStatusContent(
    status: ProvisioningStatusViewModel.Status?,
    onRefresh: () -> Unit,
    onBack: () -> Unit
) {
    val context = LocalContext.current

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.Start
    ) {
        Text(
            text = stringResource(R.string.provisioning_status_title),
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(24.dp))

        val deviceOwnerText = if (status?.isDeviceOwner == true) {
            stringResource(R.string.device_owner_yes)
        } else {
            stringResource(R.string.device_owner_no)
        }
        StatusRow(
            label = stringResource(R.string.device_owner_label),
            value = deviceOwnerText,
            talkbackLabel = stringResource(R.string.talkback_device_owner_status, deviceOwnerText)
        )

        val registeredText = if (status?.isRegistered == true) {
            stringResource(R.string.registered_yes)
        } else {
            stringResource(R.string.registered_no)
        }
        StatusRow(
            label = stringResource(R.string.registration_status_label),
            value = registeredText,
            talkbackLabel = stringResource(R.string.talkback_registration_status, registeredText)
        )

        val premiumText = status?.premiumUntil?.let {
            stringResource(R.string.premium_active_until, it)
        } ?: stringResource(R.string.premium_inactive)
        StatusRow(
            label = stringResource(R.string.premium_status_label),
            value = premiumText,
            talkbackLabel = stringResource(R.string.talkback_premium_status, premiumText)
        )

        val lastCheckText = status?.lastCheckTimeMillis?.let {
            DateFormat.getDateFormat(context).format(Date(it)) + " " +
                DateFormat.getTimeFormat(context).format(Date(it))
        } ?: stringResource(R.string.never)
        StatusRow(
            label = stringResource(R.string.last_check_label),
            value = lastCheckText,
            talkbackLabel = stringResource(R.string.talkback_last_check, lastCheckText)
        )

        Spacer(modifier = Modifier.height(32.dp))

        Button(
            onClick = onRefresh,
            modifier = Modifier
                .fillMaxWidth()
                .semantics {
                    contentDescription = d_talkback_refresh_button
                }
        ) {
            Text(stringResource(R.string.refresh_button))
        }

        Spacer(modifier = Modifier.height(16.dp))

        OutlinedButton(
            onClick = onBack,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(stringResource(R.string.back_button))
        }
    }
}

@Composable
private fun StatusRow(label: String, value: String, talkbackLabel: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
            .semantics { contentDescription = talkbackLabel }
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.weight(1f)
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.weight(1f)
        )
    }
    HorizontalDivider()
}
