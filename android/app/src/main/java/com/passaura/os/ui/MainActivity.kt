package com.passaura.os.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.res.stringResource
import com.passaura.os.R
import com.passaura.os.util.AppPreferences

class MainActivity : ComponentActivity() {
    private lateinit var prefs: AppPreferences

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = AppPreferences(this)
        
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    var showStatus by remember { mutableStateOf(false) }
                    if (prefs.isRegistered && showStatus) {
                        ProvisioningStatusScreen(prefs = prefs, onBack = { showStatus = false })
                    } else if (prefs.isRegistered) {
                        Column {
                            TextButton(onClick = { showStatus = true }) {
                                Text(stringResource(R.string.provisioning_status_title))
                            }
                            SettingsScreen(prefs = prefs)
                        }
                    } else {
                        FirstRunScreen(prefs = prefs)
                    }
                }
            }
        }
    }
}
