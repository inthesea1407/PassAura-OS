# PassAura OS (POS) - Product Makefile Snippet for Privileged APK & Overlay (MIT)
# Free tools only, no secrets. STATUS: UNTESTED in an AOSP build.

PRODUCT_PACKAGES += \
    PassAuraOS \
    PassAuraCredentialOverlay

PRODUCT_ENFORCE_RRO_TARGETS += \
    framework-res

DEVICE_PACKAGE_OVERLAYS += \
    $(LOCAL_PATH)/overlay

PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/privapp-permissions-com.passaura.os.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/privapp-permissions-com.passaura.os.xml
