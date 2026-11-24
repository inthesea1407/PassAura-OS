kotlin
package com.passaura.os.network

import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.POST

interface PassAuraApi {
    @POST("register")
    suspend fun register(@Body request: RegisterRequest): Response<RegisterResponse>

    @POST("redeem-key")
    suspend fun redeemKey(@Body request: RedeemRequest): Response<RedeemResponse>
}
