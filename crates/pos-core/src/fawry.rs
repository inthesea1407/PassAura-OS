//! Fawry server-to-server notification (V2) signature check. NOT ENABLED anywhere.
//!
//! Pure function: no network, no secrets stored. The caller supplies the merchant's
//! secure key. Format taken from Fawry's public docs ("Server To Server Notification V2"):
//! messageSignature = SHA-256 hex of
//!   fawryRefNumber + merchantRefNumber + paymentAmount + orderAmount + orderStatus
//!   + paymentMethod + paymentRefrenceNumber (empty when absent) + secureKey
//! with amounts in two-decimal form. It has not been run against a real Fawry account.

use sha2::{Digest, Sha256};

pub struct FawryNotification<'a> {
    pub fawry_ref_number: &'a str,
    pub merchant_ref_number: &'a str,
    pub payment_amount_piasters: u64,
    pub order_amount_piasters: u64,
    pub order_status: &'a str,
    pub payment_method: &'a str,
    pub payment_reference_number: &'a str,
}

fn two_decimals(piasters: u64) -> String {
    format!("{}.{:02}", piasters / 100, piasters % 100)
}

pub fn expected_signature(n: &FawryNotification, secure_key: &str) -> String {
    let s = format!(
        "{}{}{}{}{}{}{}{}",
        n.fawry_ref_number,
        n.merchant_ref_number,
        two_decimals(n.payment_amount_piasters),
        two_decimals(n.order_amount_piasters),
        n.order_status,
        n.payment_method,
        n.payment_reference_number,
        secure_key
    );
    Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// Constant-time comparison of the received signature (case-insensitive hex).
/// An empty secure key never verifies.
pub fn verify(n: &FawryNotification, secure_key: &str, received: &str) -> bool {
    if secure_key.is_empty() {
        return false;
    }
    let want = expected_signature(n, secure_key);
    let got = received.trim().to_ascii_lowercase();
    if got.len() != want.len() {
        return false;
    }
    want.bytes().zip(got.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// Only a PAID notification for exactly the expected amount may become a payment record.
pub fn is_payable(n: &FawryNotification, expected_piasters: u64) -> bool {
    n.order_status == "PAID" && n.payment_amount_piasters == expected_piasters
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paid() -> FawryNotification<'static> {
        FawryNotification {
            fawry_ref_number: "970177",
            merchant_ref_number: "M-1",
            payment_amount_piasters: 35050,
            order_amount_piasters: 35050,
            order_status: "PAID",
            payment_method: "PAYATFAWRY",
            payment_reference_number: "369552233",
        }
    }

    // Expected values were computed independently with Python hashlib.
    #[test]
    fn matches_independent_vector() {
        assert_eq!(
            expected_signature(&paid(), "secret-key"),
            "c00a259b778f24461553b73e2d1c6d6bab807d55553170ce09198e6068b05482"
        );
        let mut n = paid();
        n.order_status = "NEW";
        n.payment_reference_number = "";
        assert_eq!(
            expected_signature(&n, "secret-key"),
            "04e4c4000684ea041ebd9959a4ea5469b65e45dfd1c08d991f95daafc2154d9c"
        );
    }

    #[test]
    fn verify_accepts_good_and_rejects_bad() {
        let good = "C00A259B778F24461553B73E2D1C6D6BAB807D55553170CE09198E6068B05482";
        assert!(verify(&paid(), "secret-key", good));
        assert!(!verify(&paid(), "other-key", good));
        assert!(!verify(&paid(), "secret-key", ""));
        assert!(!verify(&paid(), "secret-key", &good[..63]));
        assert!(!verify(&paid(), "", good));
        let mut tampered = paid();
        tampered.payment_amount_piasters = 100;
        assert!(!verify(&tampered, "secret-key", good));
    }

    #[test]
    fn payable_needs_paid_status_and_exact_amount() {
        assert!(is_payable(&paid(), 35050));
        assert!(!is_payable(&paid(), 35000));
        let mut n = paid();
        n.order_status = "NEW";
        assert!(!is_payable(&n, 35050));
    }
}
