kotlin
package com.passaura.os.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import com.passaura.os.util.AppPreferences

class MainActivity : ComponentActivity() {
    private lateinit var prefs: AppPreferences

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = AppPreferences(this)
        
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    if (prefs.isRegistered) {
                        SettingsScreen(prefs = prefs)
                    } else {
                        FirstRunScreen(prefs = prefs)
                    }
                }
            }
        }
    }
}
