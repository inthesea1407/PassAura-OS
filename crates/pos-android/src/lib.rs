//! Android adapter: maps Android permission names onto pos-core actions.
//! Interface only. It does not talk to the real Android APIs yet.

use pos_core::Action;

/// Map a Android permission string to a pos-core action. Unknown names return
/// None so callers deny by default.
pub fn map_permission(name: &str) -> Option<Action> {
    match name {
        "android.permission.CAMERA" => Some(Action::Camera),
        "android.permission.RECORD_AUDIO" => Some(Action::Microphone),
        "android.permission.ACCESS_FINE_LOCATION" => Some(Action::Location),
        "android.permission.INTERNET" => Some(Action::Network),
        "android.permission.READ_EXTERNAL_STORAGE" => Some(Action::Read),
        "android.permission.WRITE_EXTERNAL_STORAGE" => Some(Action::Write),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maps_known_and_denies_unknown() {
        assert_eq!(
            map_permission("android.permission.CAMERA"),
            Some(Action::Camera)
        );
        assert_eq!(map_permission("android.permission.NOPE"), None);
    }
}
