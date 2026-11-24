# PassAura OS Android App

## Overview
PassAura OS is an Android device-owner application designed to enforce that only PassAura Premium can act as the password and credential manager on the device. It serves as the "portable layer" that works on stock Android devices (any vendor) using Device Policy APIs.

## Architecture
- **Language**: Kotlin
- **Build System**: Gradle with Kotlin DSL and Version Catalog
- **UI**: Jetpack Compose
- **Networking**: Retrofit + OkHttp
- **Testing**: JUnit + MockK
- **Integration**: Maps to `pos-core` via the `pos-android` Rust crate (JNI bindings deferred).

## Device Owner Provisioning
To enforce policies, this app must be set as the Device Owner. This requires provisioning via ADB or a QR code during device setup (or after a factory reset).

### ADB Provisioning
```bash
adb shell dpm set-device-owner com.passaura.os/.admin.PassAuraDeviceAdminReceiver

## Integration notes (integrator)
- No Gradle wrapper is committed; CI installs Gradle 8.5 (a wrapper can be generated later).
- Fixed: HTTP body logging disabled (it would log invite codes/keys); hardware-id salt moved to BuildConfig (-PposHwSalt, default is a public constant, not a secret).
- API_URL is still a placeholder. The Edge Functions live at https://<project>.supabase.co/functions/v1/ and must be deployed with JWT verification off (or the app must send the anon key). Owner-gated.
- No JNI link to pos-android; credential-manager allowlist for API 34 not implemented (only autofill service + user restrictions).
- Status: nothing run locally. CI result is the evidence.

## Round 2 integration (Qwen)
- Merged: Arabic/English strings, ErrorMessageMapper (+test), SettingsScreen using string resources.
- Kept ours over Qwen's copies: the HW_ID_SALT BuildConfig (the salt is public domain separation, not a secret, so no CI secret), the platform theme (Material3 XML theme needs an extra dependency), and the CI workflow (Gradle installed in CI, no wrapper).
- FirstRunScreen.kt from Qwen was a 9-line stub; the full screen from round 1 is kept.
