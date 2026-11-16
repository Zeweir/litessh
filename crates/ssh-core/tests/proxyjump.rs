//! Integration test for ProxyJump (skipped unless the env rig exists).
//!
//! Rig (same as manual GUI testing): sshd at $JUMP_ADDR, key auth with
//! $KEY; the jump host doubles as the target host so a single sshd
//! exercises the whole direct-tcpip -> SSH-handshake chain.
//!
//! Run: JUMP_ADDR=127.0.0.1:2222 KEY=/tmp/sshd-test/userkey \
//!      KNOWN_HOSTS=/tmp/test-known-hosts cargo test -p ssh-core --test proxyjump -- --ignored

use std::path::PathBuf;
use std::time::Duration;

use ssh_core::{AuthMethod, ConnectParams, JumpConnection, SessionEvent, SshSession};

fn rig() -> Option<(String, u16, PathBuf, PathBuf)> {
    let addr = std::env::var("JUMP_ADDR").ok()?;
    let key = PathBuf::from(std::env::var("KEY").ok()?);
    let kh = PathBuf::from(
        std::env::var("KNOWN_HOSTS").unwrap_or_else(|_| "/tmp/test-known-hosts".into()),
    );
    let (host, port) = addr.rsplit_once(':')?;
    Some((host.to_string(), port.parse().ok()?, key, kh))
}

fn params(host: &str, port: u16, key: &std::path::Path, kh: &std::path::Path) -> ConnectParams {
    ConnectParams {
        host: host.to_string(),
        port,
        username: "ubuntu".into(),
        auth: AuthMethod::PrivateKey {
            path: key.to_path_buf(),
            passphrase: None,
        },
        known_hosts_path: Some(kh.to_path_buf()),
        connect_timeout: Duration::from_secs(10),
        ..Default::default()
    }
}

#[tokio::test]
#[ignore]
async fn connect_through_jump() {
    let Some((host, port, key, kh)) = rig() else {
        eprintln!("rig env vars missing, skipping");
        return;
    };
    let jump = JumpConnection::connect(&params(&host, port, &key, &kh), None)
        .await
        .expect("jump connect");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let session = SshSession::connect(&params(&host, port, &key, &kh), tx, Some(&jump))
        .await
        .expect("session through jump");
    session.write(b"echo PJ_OK\n").await.unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut buf = Vec::new();
    while std::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(1), rx.recv()).await {
            Ok(Some(SessionEvent::Data(d))) => {
                buf.extend_from_slice(&d);
                if String::from_utf8_lossy(&buf).contains("PJ_OK") {
                    session.disconnect().await.ok();
                    return;
                }
            }
            Ok(Some(_)) | Err(_) => continue,
            Ok(None) => break,
        }
    }
    panic!(
        "no PJ_OK through jump; got: {}",
        String::from_utf8_lossy(&buf)
    );
}
