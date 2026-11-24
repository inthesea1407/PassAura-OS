package com.passaura.os.ui

import com.passaura.os.R
import org.junit.Assert.assertEquals
import org.junit.Test

class ErrorMessageMapperTest {
    @Test
    fun `maps all known error codes to correct string resources`() {
        assertEquals(R.string.error_registration_closed, ErrorMessageMapper.getErrorMessageResId("""{"error":"REGISTRATION_CLOSED"}"""))
        assertEquals(R.string.error_invite_invalid_or_used, ErrorMessageMapper.getErrorMessageResId("""{"error":"INVITE_INVALID_OR_USED"}"""))
        assertEquals(R.string.error_device_revoked, ErrorMessageMapper.getErrorMessageResId("""{"error":"DEVICE_REVOKED"}"""))
        assertEquals(R.string.error_device_already_registered, ErrorMessageMapper.getErrorMessageResId("""{"error":"DEVICE_ALREADY_REGISTERED"}"""))
        assertEquals(R.string.error_rate_limited, ErrorMessageMapper.getErrorMessageResId("""{"error":"RATE_LIMITED"}"""))
        assertEquals(R.string.error_key_invalid, ErrorMessageMapper.getErrorMessageResId("""{"error":"KEY_INVALID"}"""))
        assertEquals(R.string.error_device_invalid, ErrorMessageMapper.getErrorMessageResId("""{"error":"DEVICE_INVALID"}"""))
        
        assertEquals(R.string.error_unknown, ErrorMessageMapper.getErrorMessageResId(null))
        assertEquals(R.string.error_unknown, ErrorMessageMapper.getErrorMessageResId("""{"error":"UNKNOWN_ERROR"}"""))
        assertEquals(R.string.error_unknown, ErrorMessageMapper.getErrorMessageResId(""))
    }
}
