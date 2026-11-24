package com.passaura.os.ui

import androidx.annotation.StringRes
import com.passaura.os.R

object ErrorMessageMapper {
    @StringRes
    fun getErrorMessageResId(errorBody: String?): Int {
        if (errorBody == null) return R.string.error_unknown
        return when {
            errorBody.contains("REGISTRATION_CLOSED") -> R.string.error_registration_closed
            errorBody.contains("INVITE_INVALID_OR_USED") -> R.string.error_invite_invalid_or_used
            errorBody.contains("DEVICE_REVOKED") -> R.string.error_device_revoked
            errorBody.contains("DEVICE_ALREADY_REGISTERED") -> R.string.error_device_already_registered
            errorBody.contains("RATE_LIMITED") -> R.string.error_rate_limited
            errorBody.contains("KEY_INVALID") -> R.string.error_key_invalid
            errorBody.contains("DEVICE_INVALID") -> R.string.error_device_invalid
            else -> R.string.error_unknown
        }
    }
}
