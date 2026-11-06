use std::fmt;

/// CheckTooSlow is a BaseException in Python, so it stays outside Denied and a Denied handler cannot swallow it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    Denied(Denied),
    TooSlow,
}

impl Stop {
    pub fn as_denied(&self) -> Option<&Denied> {
        match self {
            Stop::Denied(denied) => Some(denied),
            Stop::TooSlow => None,
        }
    }

    pub fn is_remote(&self) -> bool {
        match self {
            Stop::Denied(denied) => denied.is_remote(),
            Stop::TooSlow => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied {
    reason: String,
    remote: bool,
}

impl Denied {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            remote: false,
        }
    }

    pub fn remote(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            remote: true,
        }
    }

    pub fn is_remote(&self) -> bool {
        self.remote
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for Denied {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl std::error::Error for Denied {}

#[cfg(test)]
mod tests {
    use super::{Denied, Stop};

    #[test]
    fn remote_denial_is_still_a_denial() {
        let remote = Denied::remote("outside the remote root");
        let local = Denied::new("outside the repository");
        assert!(remote.is_remote());
        assert!(!local.is_remote());
        assert_eq!(remote.to_string(), "outside the remote root");
        assert_eq!(local.reason(), "outside the repository");

        let caught = Stop::Denied(remote);
        assert!(caught.as_denied().is_some());
        assert!(caught.is_remote());
        assert!(Stop::TooSlow.as_denied().is_none());
        assert!(!Stop::TooSlow.is_remote());
    }
}
