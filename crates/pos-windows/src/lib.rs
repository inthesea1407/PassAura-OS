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
        // The real capability grants read AND write. A single Action can only
        // name one, so callers that need write must treat it separately.
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

    #[test]
    fn maps_all_known_and_rejects_odd_input() {
        assert_eq!(map_permission("microphone"), Some(Action::Microphone));
        assert_eq!(map_permission("location"), Some(Action::Location));
        assert_eq!(map_permission("internetClient"), Some(Action::Network));
        assert_eq!(map_permission("documentsLibrary"), Some(Action::Read));
        assert_eq!(map_permission("runFullTrust"), Some(Action::Execute));
        assert_eq!(map_permission(""), None);
        assert_eq!(map_permission("WEBCAM"), None);
    }
}
