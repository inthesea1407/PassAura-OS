markdown
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
