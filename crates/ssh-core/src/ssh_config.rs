//! Minimal OpenSSH `~/.ssh/config` parser: enough to import saved hosts.
//! Handles `Host` blocks (comma/space separated aliases), `HostName`,
//! `User`, `Port`, `IdentityFile`; ignores Match blocks, Includes,
//! and every other keyword. Aliases containing `*`, `?` or `!` are
//! skipped — they are patterns, not concrete hosts.

use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshConfigHost {
    /// The alias from `Host <alias>`.
    pub alias: String,
    pub host_name: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_file: Option<String>,
}

/// Parse the config text into concrete host entries, first alias per
/// usable `Host` block.
pub fn parse_ssh_config(text: &str) -> Vec<SshConfigHost> {
    let mut out = Vec::new();
    let mut cur: Option<SshConfigHost> = None;
    let mut in_match = false;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.splitn(2, char::is_whitespace);
        let key = it.next().unwrap_or("");
        let value = it.next().unwrap_or("").trim();
        // `key=value` also legal in OpenSSH config
        let (key, value) = match key.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => (key, value),
        };
        let lk = key.to_ascii_lowercase();

        match lk.as_str() {
            "host" => {
                if let Some(h) = cur.take() {
                    out.push(h);
                }
                in_match = false;
                // first non-pattern alias wins
                let alias = value
                    .split_whitespace()
                    .find(|a| !a.contains(['*', '?', '!']));
                cur = alias.map(|a| SshConfigHost {
                    alias: a.to_string(),
                    host_name: None,
                    user: None,
                    port: None,
                    identity_file: None,
                });
            }
            "match" => {
                if let Some(h) = cur.take() {
                    out.push(h);
                }
                in_match = true;
            }
            _ => {
                if in_match {
                    continue;
                }
                let Some(h) = cur.as_mut() else { continue };
                match lk.as_str() {
                    "hostname" => h.host_name = Some(unquote(value)),
                    "user" => h.user = Some(unquote(value)),
                    "port" => h.port = value.parse().ok(),
                    "identityfile" => h.identity_file = Some(unquote(value)),
                    _ => {}
                }
            }
        }
    }
    if let Some(h) = cur.take() {
        out.push(h);
    }
    // drop entries with no connection info at all
    out.retain(|h| {
        h.host_name.is_some()
            || h.user.is_some()
            || h.port.is_some()
            || h.identity_file.is_some()
    });
    out
}

/// Read and parse an ssh config file; missing file yields an empty vec.
pub fn read_ssh_config(path: &Path) -> std::io::Result<Vec<SshConfigHost>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(parse_ssh_config(&text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(e),
    }
}

fn unquote(v: &str) -> String {
    v.trim_matches('"').trim_matches('\'').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_blocks() {
        let cfg = r#"
# comment
Host *
    ServerAliveInterval 60

Host web prod-alias *
    HostName web.example.com
    User deploy
    Port 2222
    IdentityFile ~/.ssh/deploy_key

Host db
    HostName 10.0.0.5

Match host jump
    User ignored

Host empty
"#;
        let hosts = parse_ssh_config(cfg);
        assert_eq!(hosts.len(), 2); // "web" + "db"; "empty" and "*" dropped
        let h = &hosts[0];
        assert_eq!(h.alias, "web");
        assert_eq!(h.host_name.as_deref(), Some("web.example.com"));
        assert_eq!(h.user.as_deref(), Some("deploy"));
        assert_eq!(h.port, Some(2222));
        assert_eq!(h.identity_file.as_deref(), Some("~/.ssh/deploy_key"));
        // "db" has a hostname -> kept? yes: host_name present
        assert!(hosts.iter().any(|x| x.alias == "db"));
    }
}
