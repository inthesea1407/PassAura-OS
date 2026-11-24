//! Linux user-space adapter. Interface only: maps capability-style names to
//! pos-core actions. Unknown names return None so callers deny by default.
use pos_core::Action;

pub fn map_capability(name: &str) -> Option<Action> {
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
        assert_eq!(map_capability("net.connect"), Some(Action::Network));
        assert_eq!(map_capability("sys.admin"), None);
    }
}
