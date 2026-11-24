package com.passaura.os.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.passaura.os.network.NetworkClient
import com.passaura.os.network.RedeemRequest
import com.passaura.os.util.AppPreferences
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(prefs: AppPreferences) {
    val scope = rememberCoroutineScope()
    var redeemCode by remember { mutableStateOf("") }
    var isLoading by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text("PassAura OS Settings", style = MaterialTheme.typography.headlineMedium)
        Spacer(modifier = Modifier.height(24.dp))
        
        Text("Device ID: ${prefs.deviceId ?: "Unknown"}")
        Spacer(modifier = Modifier.height(8.dp))
        Text("Premium Until: ${prefs.premiumUntil ?: "Not Active"}")
        
        Spacer(modifier = Modifier.height(32.dp))
        
        OutlinedTextField(
            value = redeemCode,
            onValueChange = { redeemCode = it },
            label = { Text("Redeem Premium Code") },
            modifier = Modifier.fillMaxWidth()
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Button(
            onClick = {
                isLoading = true
                message = null
                scope.launch {
                    try {
                        val response = NetworkClient.api.redeemKey(RedeemRequest(redeemCode, prefs.deviceId!!))
                        if (response.isSuccessful) {
                            prefs.premiumUntil = response.body()?.premiumUntil
                            message = "Premium activated!"
                        } else {
                            val errorBody = response.errorBody()?.string()
                            message = "Redemption failed: ${response.code()} - $errorBody"
                        }
                    } catch (e: Exception) {
                        message = "Error: ${e.message}"
                    } finally {
                        isLoading = false
                    }
                }
            },
            enabled = !isLoading && redeemCode.isNotBlank() && prefs.deviceId != null
        ) {
            if (isLoading) CircularProgressIndicator(modifier = Modifier.size(24.dp))
            else Text("Redeem")
        }
        
        if (message != null) {
            Spacer(modifier = Modifier.height(16.dp))
            Text(message!!)
        }
    }
}
