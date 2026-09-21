/// Reserved host labels; the leftmost subdomain of `SERVER_HOST`.
pub const RESERVED: &[&str] = &["api", "sdk", "go", "preview", "mcp", "proxy"];

/// Split a `Host` header against the configured bare domain and return the
/// leftmost subdomain label, e.g. `api` from `api.links.example.com` when
/// `base_host` is `links.example.com`. Returns `None` when the host is the
/// bare domain itself or does not belong to it.
pub fn subdomain_label(host: &str, base_host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let base = base_host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host == base {
        return None;
    }
    let suffix = format!(".{base}");
    let prefix = host.strip_suffix(&suffix)?;
    prefix
        .split('.')
        .next()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

pub fn is_reserved(label: &str) -> bool {
    RESERVED.contains(&label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_reserved_label() {
        assert_eq!(
            subdomain_label("api.links.example.com", "links.example.com"),
            Some("api".into())
        );
    }

    #[test]
    fn bare_host_has_no_label() {
        assert_eq!(
            subdomain_label("links.example.com", "links.example.com"),
            None
        );
    }

    #[test]
    fn foreign_host_is_none() {
        assert_eq!(subdomain_label("evil.com", "links.example.com"), None);
    }
}
