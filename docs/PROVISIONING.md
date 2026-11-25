# Device Owner Provisioning

Status: draft. Not tested on a real device. Nothing here has been audited.
The steps follow Android's documented provisioning extras. They are not yet
verified against a PassAura release build, because no signed release APK exists.

PassAura OS must be the **Device Owner** to enforce its policies (autofill
restriction, unknown-source block). This cannot be done from inside the app.
It needs a freshly factory-reset device, or a device with no accounts at all
(no Google, local or work account). Once an account exists, `set-device-owner`
fails with "already some accounts on the device".

Pick one method.

## Method 1: QR code (end users)

1. Factory-reset the device and connect it to Wi-Fi (it downloads the APK).
2. On the Welcome screen, tap the same spot 6 times to open the QR scanner.
   The exact gesture can vary by manufacturer.
3. Scan a QR code made from this JSON:

```json
{
  "android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME": "com.passaura.os/.admin.PassAuraDeviceAdminReceiver",
  "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION": "<HTTPS_URL_OF_RELEASE_APK>",
  "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_CHECKSUM": "<URLSAFE_BASE64_SHA256_OF_APK_FILE>",
  "android.app.extra.PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM": "<URLSAFE_BASE64_SHA256_OF_SIGNING_CERT>",
  "android.app.extra.PROVISIONING_LEAVE_ALL_SYSTEM_APPS_ENABLED": false,
  "android.app.extra.PROVISIONING_ADMIN_EXTRAS_BUNDLE": {
    "invite_code": "<YOUR_INVITE_CODE_OR_EMPTY_FOR_SEED>"
  }
}
```

Notes:
- The package checksum is of the APK file. The signature checksum is of the
  signing certificate. They are different values. Use URL-safe base64 for both.
- Without the download location and package checksum, the device cannot fetch
  and verify the app.
- Do not put a real invite code in a QR code you share. Codes are single-use.

## Method 2: ADB (developers)

0. Factory-reset the device, skip account setup, enable Developer options
   (tap Build number 7 times) and USB debugging.
1. Check the connection and that no accounts exist:
```
adb devices
adb shell dumpsys account
```
2. Install the APK (a debug build for testing):
```
adb install app/build/outputs/apk/debug/app-debug.apk
```
3. Set the device owner:
```
adb shell dpm set-device-owner com.passaura.os/.admin.PassAuraDeviceAdminReceiver
```
   Expected: `Success: Device owner set to package ...`. On a multi-user device
   you may need to add `--user 0`.
4. Verify:
```
adb shell dumpsys device_policy | grep -A 2 "Device Owner"
```

## Removing it

`adb shell dpm remove-active-admin com.passaura.os/.admin.PassAuraDeviceAdminReceiver`
works only for builds marked `testOnly` (debug builds). A release build cannot
be removed this way. Use a factory reset.

---

# التهيئة كمالك للجهاز (Device Owner)

الحالة: مسودة، لم تُجرَّب على جهاز حقيقي ولم تُدقَّق.

يجب أن يكون PassAura OS مالك الجهاز لتطبيق سياساته. هذا لا يتم من داخل التطبيق. يلزم جهاز بعد إعادة ضبط المصنع وبدون أي حساب (جوجل أو محلي أو عمل). بعد إضافة حساب يفشل الأمر.

## الطريقة 1: رمز QR
1. أعد ضبط المصنع واتصل بالواي فاي.
2. في شاشة الترحيب المس نفس المكان 6 مرات لفتح الماسح (قد يختلف حسب الشركة).
3. امسح رمز QR المبني على JSON أعلاه. مجموع التحقق للحزمة (APK) يختلف عن مجموع التحقق لشهادة التوقيع، وكلاهما SHA-256 بصيغة base64 الآمنة للروابط.

## الطريقة 2: ADB
0. أعد ضبط المصنع، تخطَّ الحسابات، فعّل خيارات المطور وتصحيح USB.
1. `adb devices` ثم `adb shell dumpsys account` للتأكد من عدم وجود حسابات.
2. ثبّت الحزمة بـ `adb install`.
3. `adb shell dpm set-device-owner com.passaura.os/.admin.PassAuraDeviceAdminReceiver` (وأضف `--user 0` عند الحاجة).
4. تحقق: `adb shell dumpsys device_policy | grep -A 2 "Device Owner"`

## الإزالة
أمر `dpm remove-active-admin` يعمل فقط لإصدارات الاختبار (testOnly). إصدار الإنتاج يحتاج إعادة ضبط المصنع.
