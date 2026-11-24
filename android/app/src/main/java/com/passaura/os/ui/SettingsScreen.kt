package com.passaura.os.ui

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
import com.passaura.os.network.NetworkClient
import com.passaura.os.network.RedeemRequest
import com.passaura.os.util.AppPreferences
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(prefs: AppPreferences) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var redeemCode by remember { mutableStateOf("") }
    var isLoading by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    var isError by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = stringResource(R.string.settings_title), 
            style = MaterialTheme.typography.headlineMedium
        )
        Spacer(modifier = Modifier.height(24.dp))
        
        Text(
            text = stringResource(R.string.device_id_label, prefs.deviceId ?: stringResource(R.string.unknown)),
            modifier = Modifier.padding(horizontal = 16.dp)
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = stringResource(R.string.premium_until_label, prefs.premiumUntil ?: stringResource(R.string.not_active)),
            modifier = Modifier.padding(horizontal = 16.dp)
        )
        
        Spacer(modifier = Modifier.height(32.dp))
        
        OutlinedTextField(
            value = redeemCode,
            onValueChange = { redeemCode = it },
            label = { Text(stringResource(R.string.redeem_code_label)) },
            modifier = Modifier
                .fillMaxWidth()
                .semantics { contentDescription = stringResource(R.string.redeem_code_label) },
            enabled = !isLoading
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Button(
            onClick = {
                isLoading = true
                message = null
                isError = false
                scope.launch {
                    try {
                        val response = NetworkClient.api.redeemKey(RedeemRequest(redeemCode, prefs.deviceId!!))
                        if (response.isSuccessful) {
                            prefs.premiumUntil = response.body()?.premiumUntil
                            message = context.getString(R.string.premium_activated)
                        } else {
                            val errorBody = response.errorBody()?.string()
                            message = context.getString(ErrorMessageMapper.getErrorMessageResId(errorBody))
                            isError = true
                        }
                    } catch (e: Exception) {
                        message = context.getString(R.string.error_unknown)
                        isError = true
                    } finally {
                        isLoading = false
                    }
                }
            },
            enabled = !isLoading && redeemCode.isNotBlank() && prefs.deviceId != null,
            modifier = Modifier.semantics { contentDescription = stringResource(R.string.redeem_button) }
        ) {
            if (isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(24.dp),
                    color = MaterialTheme.colorScheme.onPrimary
                )
            } else {
                Text(stringResource(R.string.redeem_button))
            }
        }
        
        if (message != null) {
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = message!!, 
                color = if (isError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface
            )
        }
    }
}
