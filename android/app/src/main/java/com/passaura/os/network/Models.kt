kotlin
package com.passaura.os.network

import com.google.gson.annotations.SerializedName

data class RegisterRequest(
    @SerializedName("invite_code") val inviteCode: String,
    @SerializedName("hardware_id_hash") val hardwareIdHash: String
)

data class RegisterResponse(
    @SerializedName("device_id") val deviceId: String
)

data class RedeemRequest(
    @SerializedName("code") val code: String,
    @SerializedName("device_id") val deviceId: String
)

data class RedeemResponse(
    @SerializedName("premium_until") val premiumUntil: String?
)

data class ApiError(
    @SerializedName("error") val error: String?
)
