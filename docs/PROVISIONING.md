# Device Owner Provisioning

PassAura OS must be provisioned as the **Device Owner** to enforce its security policies (autofill restriction, unknown-source block, etc.). This cannot be done from within the app after first launch; it must be performed on a freshly factory-reset device (or a device with no user accounts yet) via either a QR code or ADB.

> **Important**: Once a user account is added to the device, `set-device-owner` will fail. Perform provisioning **before** the "Welcome" setup screen, or after a full factory reset.

---

## Method 1: QR Code Provisioning (Recommended for end users)

1. Factory-reset the device (`Settings → System → Reset → Factory data reset`).
2. On the "Welcome" setup screen, tap the same corner **6 times** to reveal the QR provisioning entry point (or follow your OEM's enterprise enrollment flow).
3. Scan the QR code below (generated from the JSON payload).

### QR Payload (JSON)

```json
{
  "android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME": "com.passaura.os/.admin.PassAuraDeviceAdminReceiver",
  "android.app.extra.PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM": "<BASE64_SHA256_OF_RELEASE_APK>",
  "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_NAME": "com.passaura.os",
  "android.app.extra.PROVISIONING_LEAVE_ALL_SYSTEM_APPS_ENABLED": false,
  "android.app.extra.PROVISIONING_ADMIN_EXTRAS_BUNDLE": {
    "invite_code": "<YOUR_INVITE_CODE_OR_EMPTY_FOR_SEED>"
  }
}

<!-- Assembled from fragments; sections below are the remaining code steps and the Arabic translation. Review before commit. -->

**Step 1 — Connect and verify**
```
adb devices
# Confirm your device is listed as "device"
```

**Step 2 — Install the APK**
```
adb install app/build/outputs/apk/debug/app-debug.apk
```

**Step 3 — Set device owner**
```
adb shell dpm set-device-owner com.passaura.os/.admin.PassAuraDeviceAdminReceiver
```

**Expected output:**
```
Success: Device owner set to package ComponentInfo{com.passaura.os/com.passaura.os.admin.PassAuraDeviceAdminReceiver}
Active admin set to component {com.passaura.os/com.passaura.os.admin.PassAuraDeviceAdminReceiver}
```

**Step 5 — Verify**
```
adb shell dumpsys device_policy | grep -A 2 "Device Owner"
```

**Only possible if you have physical access and ADB:**
```
adb shell dpm remove-active-admin com.passaura.os/.admin.PassAuraDeviceAdminReceiver
```

**الخطوة 1 — الاتصال والتحقق**
```
adb devices
# تأكد من ظهور جهازك كـ "device"
```

**الخطوة 2 — تثبيت حزمة APK**
```
adb install app/build/outputs/apk/debug/app-debug.apk
```

**الخطوة 3 — تعيين مالك الجهاز**
```
adb shell dpm set-device-owner com.passaura.os/.admin.PassAuraDeviceAdminReceiver
```

**الناتج المتوقع:**
```
Success: Device owner set to package ComponentInfo{com.passaura.os/com.passaura.os.admin.PassAuraDeviceAdminReceiver}
Active admin set to component {com.passaura.os/com.passaura.os.admin.PassAuraDeviceAdminReceiver}
```

**الخطوة 5 — التحقق**
```
adb shell dumpsys device_policy | grep -A 2 "Device Owner"
```

**يمكن فقط إذا كان لديك وصول فعلي و ADB:**
```
adb shell dpm remove-active-admin com.passaura.os/.admin.PassAuraDeviceAdminReceiver
```
