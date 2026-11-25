//! Linux user-space adapter. Interface only: maps capability-style names to
//! pos-core actions. Unknown names return None so callers deny by default.
use pos_core::Action;

pub fn map_permission(name: &str) -> Option<Action> {
    match name {
        "fs.read" => Some(Action::Read),
        "fs.write" => Some(Action::Write),
        "proc.exec" => Some(Action::Execute),
        "net.connect" => Some(Action::Network),
        "dev.video" => Some(Action::Camera),
        "dev.audio.capture" => Some(Action::Microphone),
        "geo.read" => Some(Action::Location),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maps_known_and_denies_unknown() {
        assert_eq!(map_permission("net.connect"), Some(Action::Network));
        assert_eq!(map_permission("sys.admin"), None);
    }

    #[test]
    fn maps_all_known_and_rejects_odd_input() {
        assert_eq!(map_permission("fs.read"), Some(Action::Read));
        assert_eq!(map_permission("fs.write"), Some(Action::Write));
        assert_eq!(map_permission("proc.exec"), Some(Action::Execute));
        assert_eq!(map_permission("dev.video"), Some(Action::Camera));
        assert_eq!(
            map_permission("dev.audio.capture"),
            Some(Action::Microphone)
        );
        assert_eq!(map_permission("geo.read"), Some(Action::Location));
        assert_eq!(map_permission(""), None);
        assert_eq!(map_permission("NET.CONNECT"), None);
    }
}
