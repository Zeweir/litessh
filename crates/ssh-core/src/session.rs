use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{bail, Context};
use bytes::Bytes;
use russh::{
    client::{self, Handle, Handler},
    keys::{load_secret_key, HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate},
    ChannelMsg, ChannelWriteHalf,
};
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub enum AuthMethod {
    Password(String),
    PrivateKey {
        path: PathBuf,
        passphrase: Option<String>,
    },
}

#[derive(Debug)]
pub struct ConnectParams {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: AuthMethod,
    pub term: String,
    pub cols: u32,
    pub rows: u32,
    pub connect_timeout: Duration,
}

impl Default for ConnectParams {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 22,
            username: String::new(),
            auth: AuthMethod::Password(String::new()),
            term: "xterm-256color".into(),
            cols: 80,
            rows: 24,
            connect_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone)]
pub enum SessionEvent {
    Data(Vec<u8>),
    Eof,
    ExitStatus(u32),
    Closed,
}

fn expand_tilde(path: &std::path::Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/").or_else(|| s.strip_prefix("~\\")) {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            return PathBuf::from(home).join(rest);
        }
    }
    path.to_path_buf()
}

/// Accepts every host key for now.
/// TODO: verify against a known_hosts store (TOFU) instead.
struct ClientHandler;

impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// One live SSH session: a PTY channel plus a background task pumping
/// server output into `SessionEvent`s.
pub struct SshSession {
    write_half: ChannelWriteHalf<client::Msg>,
    _handle: Handle<ClientHandler>,
}

impl SshSession {
    pub async fn connect(
        params: &ConnectParams,
        events: mpsc::UnboundedSender<SessionEvent>,
    ) -> anyhow::Result<Self> {
        let mut config = client::Config::default();
        config.inactivity_timeout = Some(Duration::from_secs(30));
        let config = Arc::new(config);

        let mut handle = tokio::time::timeout(
            params.connect_timeout,
            client::connect(config, (params.host.as_str(), params.port), ClientHandler),
        )
        .await
        .context("connection timed out")?
        .context("tcp/ssh handshake failed")?;

        match &params.auth {
            AuthMethod::Password(password) => {
                let res = handle
                    .authenticate_password(&params.username, password)
                    .await?;
                if !res.success() {
                    bail!("authentication failed");
                }
            }
            AuthMethod::PrivateKey { path, passphrase } => {
                let path = expand_tilde(path);
                let key = load_secret_key(&path, passphrase.as_deref())
                    .with_context(|| format!("loading key {}", path.display()))?;
                let hash: Option<HashAlg> = handle.best_supported_rsa_hash().await?.flatten();
                let res = handle
                    .authenticate_publickey(
                        &params.username,
                        PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                    )
                    .await?;
                if !res.success() {
                    bail!("authentication failed");
                }
            }
        }

        let channel = handle.channel_open_session().await?;
        channel
            .request_pty(true, &params.term, params.cols, params.rows, 0, 0, &[])
            .await
            .context("request_pty failed")?;
        channel
            .request_shell(true)
            .await
            .context("request_shell failed")?;

        let (mut read_half, write_half) = channel.split();
        tokio::spawn(async move {
            while let Some(msg) = read_half.wait().await {
                let ev = match msg {
                    ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                        SessionEvent::Data(data.to_vec())
                    }
                    ChannelMsg::Eof => SessionEvent::Eof,
                    ChannelMsg::ExitStatus { exit_status } => SessionEvent::ExitStatus(exit_status),
                    ChannelMsg::Close => SessionEvent::Closed,
                    _ => continue,
                };
                if events.send(ev).is_err() {
                    break;
                }
            }
        });

        Ok(Self {
            write_half,
            _handle: handle,
        })
    }

    pub async fn write(&self, data: &[u8]) -> anyhow::Result<()> {
        self.write_half
            .data_bytes(Bytes::copy_from_slice(data))
            .await?;
        Ok(())
    }

    pub async fn resize(&self, cols: u32, rows: u32) -> anyhow::Result<()> {
        self.write_half.window_change(cols, rows, 0, 0).await?;
        Ok(())
    }

    pub async fn disconnect(&self) -> anyhow::Result<()> {
        self.write_half.close().await?;
        Ok(())
    }
}
