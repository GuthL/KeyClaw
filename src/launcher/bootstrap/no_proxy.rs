#[derive(Debug, PartialEq, Eq)]
enum NoProxyEntry {
    Wildcard,
    Host {
        raw: String,
        host: String,
        is_suffix: bool,
        has_port: bool,
    },
}

impl NoProxyEntry {
    fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return None;
        }
        if raw == "*" {
            return Some(Self::Wildcard);
        }

        let (host, has_port) = split_host_port(raw);
        let host = host.to_lowercase();
        let is_suffix = host.starts_with('.');
        let host = host.trim_start_matches('.').to_string();
        if host.is_empty() {
            return None;
        }

        Some(Self::Host {
            raw: raw.to_string(),
            host,
            is_suffix,
            has_port,
        })
    }

    fn match_reason(&self, intercepted_host: &str) -> Option<String> {
        match self {
            Self::Wildcard => Some("NO_PROXY=*".to_string()),
            Self::Host {
                raw,
                host,
                is_suffix,
                has_port,
            } => {
                let exact = intercepted_host == host;
                let suffix = intercepted_host.ends_with(&format!(".{host}"));
                if !(exact || *is_suffix && suffix) {
                    return None;
                }

                if *is_suffix || *has_port {
                    Some(format!(
                        "NO_PROXY includes {raw} (matches {intercepted_host})"
                    ))
                } else {
                    Some(format!("NO_PROXY includes {raw}"))
                }
            }
        }
    }
}

pub(crate) fn launcher_bypass_risk(no_proxy: &str, hosts: &[String]) -> Option<String> {
    let entries = no_proxy
        .split(',')
        .filter_map(NoProxyEntry::parse)
        .collect::<Vec<_>>();

    for host in hosts
        .iter()
        .filter_map(|host| normalize_no_proxy_host(host))
    {
        for entry in &entries {
            if let Some(reason) = entry.match_reason(&host) {
                return Some(reason);
            }
        }
    }

    None
}

fn normalize_no_proxy_host(host: &str) -> Option<String> {
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    if host.contains('*') || host.contains('?') {
        return None;
    }
    Some(split_host_port(host).0.to_lowercase())
}

fn split_host_port(value: &str) -> (&str, bool) {
    let value = value.trim();
    if value.matches(':').count() == 1 {
        if let Some((host, port)) = value.rsplit_once(':') {
            if !host.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) {
                return (host, true);
            }
        }
    }
    (value, false)
}
