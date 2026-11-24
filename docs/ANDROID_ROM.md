# PassAura OS (POS) Android ROM Layer & Device-Owner Integration

PassAura OS (POS) is licensed under **MIT**, uses **free tools only**, requires **no secrets**, and follows the zero-budget policy (`docs/ROADMAP_ZERO_BUDGET.md`) with official releases signed solely by the project owner and **PassAura** (`com.passaura.os`) as the sole approved password/credential manager.

## ROM-Side Artifacts (`android-rom/`)

- `android-rom/overlay/frameworks/base/core/res/res/values/config.xml`: RRO/resource overlay setting `com.passaura.os` as the default credential manager and autofill service.
- `android-rom/sepolicy/passaura_os.te` & `android-rom/sepolicy/passaura_os.fc`: Draft SELinux domain and file context rules for `passaura_os_app` (all rules marked `UNTESTED`).
- `android-rom/privapp-permissions-com.passaura.os.xml`: Privileged permissions allowlist for `com.passaura.os` installed under `/system/priv-app/`.
- `android-rom/device.mk`: Product makefile snippet wiring `PassAuraOS`, the overlay, and privileged permissions into the AOSP product image.

## ROM Layer vs. App Device-Owner Layer

### What the ROM Layer Enforces
- **Default Provider Pinning:** Sets `com.passaura.os` as the default credential/autofill provider at the framework resource/overlay level.
- **Privileged Placement & SELinux Boundaries:** Places `PassAuraOS` in `/system/priv-app/` with explicit `privapp-permissions` and `sepolicy` file/domain labels (`passaura_os_data_file`).
- **Firmware-Level Integrity:** Persists across factory resets when flashed as part of an owner-signed AOSP build.

### What the ROM Layer Cannot Enforce Alone
- **Runtime Account, Invite, and Device Registry State:** Cannot by itself track one-time invite codes (2 invites per member, first 1,000 devices free), owner dashboard modes (`Free-invite` / `Paid` / `Closed`), or perpetual membership rules without app/backend/registry logic.
- **Dynamic User/Profile Policy Enforcement:** Runtime device-owner/DPC policies handle user-level provisioning states and app-level controls that static build-time overlays alone do not manage dynamically.

### What the App / Device-Owner Layer Enforces
- **Invite & Membership Lifecycle:** Enforces single-use invite tokens, invite quotas, device registration, and owner-controlled mode switches (`Free-invite`, `Paid`, `Closed`).
- **Runtime Credential/Policy Guardrails:** Coordinates app-level credential/autofill checks and policy enforcement on top of the ROM baseline.

### What the App / Device-Owner Layer Cannot Enforce Alone
- **Surviving Factory Reset or Bootloader/Partition Tampering:** User-space device-owner state can be wiped on factory reset or bypassed if the underlying ROM/sepolicy is unmodified.
- **Kernel/SELinux Mandatory Access Control:** App code cannot define new SELinux domain types (`passaura_os_app`) or `neverallow` rules on its own.

## Status & Verification Scope

نواة أمنية وأدوات نموذجية مختبَرة في CI والمحاكيات، ولا يوجد إصدار مختبَر على عتاد أو مدقَّق خارجيًا بعد.
