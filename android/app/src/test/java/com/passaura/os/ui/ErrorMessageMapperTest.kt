package com.passaura.os.ui

import com.passaura.os.R
import org.junit.Assert.assertEquals
import org.junit.Test

class ErrorMessageMapperTest {
    @Test
    fun `maps all register error codes to correct string resources`() {
        assertEquals(R.string.error_registration_closed,
            ErrorMessageMapper.getErrorMessageResId("""{"error":"REGISTRATION_CLOSED"}"""))
        assertEquals(R.string.error_invite_invalid_or_used,
            ErrorMessageMapper.getErrorMessageResId("""{"error":"INVITE_INVALID_OR_USED"}"""))
        assertEquals(R.string.error_device_revoked,
            ErrorMessageMapper.getErrorMessageResId("""{"error":"DEVICE_REVOKED"}"""))
        assertEquals(R.string.error_device_already_registered,
            ErrorMessageMapper.getErrorMessageResId("""{"error":"DEVICE_ALREADY_REGISTERED"}"""))
        assertEquals(R.string.error_rate_limited,
            ErrorMessageMapper.getErrorMessageResId("""{"error":"RATE_LIMITED"}"""))
    }

    @Test
    fun `maps all redeem error codes to correct string resources`() {
        assertEquals(R.string.error_key_invalid,
            ErrorMessageMapper.getErrorMessageResId("""{"error":"KEY_INVALID"}"""))
        assertEquals(R.string.error_device_invalid,
            ErrorMessageMapper.getErrorMessageResId("""{"error":"DEVICE_INVALID"}"""))
        // RATE_LIMITED is shared between register and redeem
        assertEquals(R.string.error_rate_limited,
            ErrorMessageMapper.getErrorMessageResId("""{"error":"RATE_LIMITED"}"""))
    }

    @Test
    fun `maps bad input to bad input resource`() {
        assertEquals(R.string.error_bad_input,
            ErrorMessageMapper.getErrorMessageResId("""{"error":"BAD_INPUT"}"""))
    }

    @Test
    fun `unknown and null error bodies fall back to unknown`() {
        assertEquals(R.string.error_unknown, ErrorMessageMapper.getErrorMessageResId(null))
        assertEquals(R.string.error_unknown, ErrorMessageMapper.getErrorMessageResId(""))
        assertEquals(R.string.error_unknown, ErrorMessageMapper.getErrorMessageResId("   "))
        assertEquals(R.string.error_unknown,
            ErrorMessageMapper.getErrorMessageResId("""{"error":"SOMETHING_ELSE"}"""))
    }

    @Test
    fun `error code detection is substring-based and tolerant of surrounding JSON`() {
        assertEquals(R.string.error_device_revoked,
            ErrorMessageMapper.getErrorMessageResId("""{"error":"DEVICE_REVOKED","hint":"contact support"}"""))
        assertEquals(R.string.error_rate_limited,
            ErrorMessageMapper.getErrorMessageResId("""code=429 error=RATE_LIMITED"""))
    }
}
