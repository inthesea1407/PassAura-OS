//! Windows adapter: maps Windows permission names onto pos-core actions.
//! Interface only. It does not talk to the real Windows APIs yet.

use pos_core::Action;

/// Map a Windows permission string to a pos-core action. Unknown names return
/// None so callers deny by default.
pub fn map_permission(name: &str) -> Option<Action> {
    match name {
        "webcam" => Some(Action::Camera),
        "microphone" => Some(Action::Microphone),
        "location" => Some(Action::Location),
        "internetClient" => Some(Action::Network),
        "documentsLibrary" => Some(Action::Read),
        "runFullTrust" => Some(Action::Execute),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maps_known_and_denies_unknown() {
        assert_eq!(map_permission("webcam"), Some(Action::Camera));
        assert_eq!(map_permission("nope"), None);
    }
}
