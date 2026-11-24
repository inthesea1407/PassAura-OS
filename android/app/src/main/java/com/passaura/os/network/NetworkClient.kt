package com.passaura.os.network

import com.passaura.os.BuildConfig
import okhttp3.OkHttpClient
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit

object NetworkClient {
    val api: PassAuraApi by lazy {
        // No logging interceptor or EventListener on purpose: request bodies carry
        // invite codes and premium keys. Do not add one, not even in debug builds.
        val client = OkHttpClient.Builder()
            // Do not silently resend a POST on a new connection (duplicate registration risk).
            .retryOnConnectionFailure(false)
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .build()

        Retrofit.Builder()
            .baseUrl(BuildConfig.API_URL)
            .client(client)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(PassAuraApi::class.java)
    }
}
