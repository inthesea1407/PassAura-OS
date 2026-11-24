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
import com.passaura.os.network.RegisterRequest
import com.passaura.os.util.AppPreferences
import com.passaura.os.util.DeviceUtils
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FirstRunScreen(prefs: AppPreferences) {
    val d_invite_code_label = stringResource(R.string.invite_code_label)
    val d_register_button = stringResource(R.string.register_button)
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var inviteCode by remember { mutableStateOf("") }
    var isLoading by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = stringResource(R.string.register_device), 
            style = MaterialTheme.typography.headlineMedium
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = stringResource(R.string.seed_member_info), 
            style = MaterialTheme.typography.bodyMedium
        )
        Spacer(modifier = Modifier.height(16.dp))
        
        OutlinedTextField(
            value = inviteCode,
            onValueChange = { inviteCode = it },
            label = { Text(stringResource(R.string.invite_code_label)) },
            modifier = Modifier
                .fillMaxWidth()
                .semantics { contentDescription = d_invite_code_label },
            enabled = !isLoading
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Button(
            onClick = {
                isLoading = true
                errorMessage = null
                scope.launch {
                    try {
                        val hash = DeviceUtils.getHardwareIdHash(context)
                        val response = NetworkClient.api.register(RegisterRequest(inviteCode, hash))
                        if (response.isSuccessful) {
                            prefs.deviceId = response.body()?.deviceId
                        } else {
                            val errorBody = response.errorBody()?.string()
                            val resId = ErrorMessageMapper.getErrorMessageResId(errorBody)
                            errorMessage = context.getString(resId)
                        }
                    } catch (e: Exception) {
                        errorMessage = context.getString(R.string.error_unknown)
                    } finally {
                        isLoading = false
                    }
                }
            },
            enabled = !isLoading,
            modifier = Modifier.semantics { contentDescription = d_register_button }
        ) {
            if (isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(24.dp),
                    color = MaterialTheme.colorScheme.onPrimary
                )
            } else {
                Text(stringResource(R.string.register_button))
            }
        }
        
        if (errorMessage != null) {
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = errorMessage!!, 
                color = MaterialTheme.colorScheme.error
            )
        }
    }
}
