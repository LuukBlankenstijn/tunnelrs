pub fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_end_matches('.');
    let host = host.trim_end_matches('.');
    let mut pattern_labels = pattern.split('.');
    let mut host_labels = host.split('.');
    loop {
        match (pattern_labels.next(), host_labels.next()) {
            (None, None) => return true,
            (Some("*"), Some(label)) if !label.is_empty() => {}
            (Some(expected), Some(label)) if expected.eq_ignore_ascii_case(label) => {}
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::host_matches;

    #[test]
    fn wildcard_matches_exactly_one_label() {
        assert!(host_matches("*.foo.example.com", "a.foo.example.com"));
        assert!(!host_matches("*.foo.example.com", "a.b.foo.example.com"));
        assert!(!host_matches("*.foo.example.com", "foo.example.com"));
        assert!(!host_matches("*.foo.example.com", ".foo.example.com"));
    }

    #[test]
    fn exact_patterns_compare_case_insensitively() {
        assert!(host_matches("App.Example.com", "app.example.com."));
        assert!(!host_matches("app.example.com", "app.example.org"));
    }
}
