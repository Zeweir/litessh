use std::{io::Write as _, path::Path, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{bail, Context};
use bytes::Bytes;
use russh::{
    client::{self, Handle, Handler},
    keys::{
        known_hosts, load_secret_key, HashAlg, PrivateKeyWithHashAlg, PublicKey,
        PublicKeyOrCertificate,
    },
    Channel, ChannelMsg, ChannelOpenFailure, ChannelWriteHalf,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot, Mutex},
    task::JoinHandle,
};

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
    /// OpenSSH-format known_hosts file used to verify the server key.
    /// `None` skips verification entirely (accepts any key).
    pub known_hosts_path: Option<PathBuf>,
    /// Sink for interactive host-key confirmation (TOFU). `None` rejects
    /// unknown or changed keys.
    pub hostkey_prompt_tx: Option<HostKeyPromptTx>,
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
            known_hosts_path: None,
            hostkey_prompt_tx: None,
        }
    }
}

/// Interactive confirmation for an unverified host key. The front-end
/// fills `decision` with `true` (trust) or `false` (reject).
pub struct HostKeyPrompt {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    /// e.g. `SHA256:abc...`
    pub fingerprint: String,
    /// The presented key differs from the stored one: possible MITM.
    pub changed: bool,
    pub decision: oneshot::Sender<bool>,
}

pub type HostKeyPromptTx = mpsc::UnboundedSender<HostKeyPrompt>;
/// Channel handed to the client by the server for a `forwarded-tcpip` open,
/// tagged with the remote port it was connected to.
type ForwardedChannel = (Channel<client::Msg>, u32);
type ForwardedTx = mpsc::UnboundedSender<ForwardedChannel>;
type ForwardedRx = mpsc::UnboundedReceiver<ForwardedChannel>;

/// How long `check_server_key` waits for a user decision.
const HOSTKEY_PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

/// Extra headroom on the outer connect timeout while a prompt may block
/// the handshake.
const HOSTKEY_PROMPT_GRACE: Duration = Duration::from_secs(125);

#[derive(Debug, Clone)]
pub enum SessionEvent {
    Data(Vec<u8>),
    Eof,
    ExitStatus(u32),
    Closed,
}

/// Expand a leading `~/` (or `~\`) to the user's home directory.
pub fn expand_tilde(path: &std::path::Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/").or_else(|| s.strip_prefix("~\\")) {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            return PathBuf::from(home).join(rest);
        }
    }
    path.to_path_buf()
}

struct ClientHandler {
    host: String,
    port: u16,
    known_hosts_path: Option<PathBuf>,
    prompt_tx: Option<HostKeyPromptTx>,
    /// Channels the server opens for remote (-R) forwards.
    forwarded_tx: ForwardedTx,
}

/// Remove every stored host-key line matching `host`/`[host]:port`.
fn remove_host_key_lines(path: &Path, host: &str, port: u16) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let content = std::fs::read_to_string(path)?;
    let bracketed = format!("[{host}]:{port}");
    let kept: Vec<&str> = content
        .lines()
        .filter(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return true;
            }
            let mut fields = line.split_whitespace();
            let mut hosts_field = fields.next().unwrap_or("");
            if hosts_field.starts_with('@') {
                hosts_field = fields.next().unwrap_or("");
            }
            !hosts_field.split(',').any(|h| h == host || h == bracketed)
        })
        .collect();
    let mut out = kept.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    let mut file = std::fs::File::create(path)?;
    file.write_all(out.as_bytes())
}

impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let pubkey = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            PublicKeyOrCertificate::Certificate(cert) => {
                PublicKey::new(cert.public_key().clone(), "")
            }
        };
        let Some(path) = &self.known_hosts_path else {
            // No store configured: keep accepting (opt-out of verification).
            return Ok(true);
        };

        let changed =
            match known_hosts::check_known_hosts_path(&self.host, self.port, &pubkey, path) {
                Ok(true) => return Ok(true),
                Ok(false) => false,
                Err(russh::keys::Error::KeyChanged { .. }) => true,
                Err(_) => false, // unreadable/missing file -> treat as unknown host
            };

        let Some(tx) = &self.prompt_tx else {
            // Non-interactive: never silently trust.
            return Ok(false);
        };
        let (decision, rx) = oneshot::channel();
        if tx
            .send(HostKeyPrompt {
                host: self.host.clone(),
                port: self.port,
                algorithm: pubkey.algorithm().to_string(),
                fingerprint: pubkey.fingerprint(HashAlg::Sha256).to_string(),
                changed,
                decision,
            })
            .is_err()
        {
            return Ok(false);
        }
        let accepted = tokio::time::timeout(HOSTKEY_PROMPT_TIMEOUT, rx)
            .await
            .unwrap_or(Ok(false))
            .unwrap_or(false);
        if !accepted {
            return Ok(false);
        }
        if changed {
            let _ = remove_host_key_lines(path, &self.host, self.port);
        }
        if let Err(e) = known_hosts::learn_known_hosts_path(&self.host, self.port, &pubkey, path) {
            tracing::warn!("failed to record host key: {e}");
        }
        Ok(true)
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<client::Msg>,
        _connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        if self.forwarded_tx.send((channel, connected_port)).is_ok() {
            reply.accept().await;
        } else {
            reply.reject(ChannelOpenFailure::ConnectFailed).await;
        }
        Ok(())
    }
}

/// One live SSH session: a PTY channel plus a background task pumping
/// server output into `SessionEvent`s.
/// A running local (-L) or remote (-R) forward. Drop `task` to stop it.
pub struct Forward {
    /// Port actually bound (relevant when 0 was requested).
    pub bound_port: u16,
    pub task: JoinHandle<()>,
}

/// Route table + demux task for remote (-R) forwards on one session.
pub struct RemoteForwarder {
    routes: Arc<Mutex<std::collections::HashMap<u32, (String, u16)>>>,
    _demux: JoinHandle<()>,
}

impl RemoteForwarder {
    /// Register `remote_port -> target` so newly accepted channels are
    /// bridged there.
    pub async fn add_route(&self, remote_port: u32, target_host: String, target_port: u16) {
        self.routes
            .lock()
            .await
            .insert(remote_port, (target_host, target_port));
    }

    pub async fn remove_route(&self, remote_port: u32) {
        self.routes.lock().await.remove(&remote_port);
    }
}

pub struct SshSession {
    write_half: ChannelWriteHalf<client::Msg>,
    handle: Handle<ClientHandler>,
    /// Taken by `start_remote_forwarder` (one per session).
    forwarded_rx: Mutex<Option<ForwardedRx>>,
}

/// SSH protocol handshake + authentication over a transport — TCP direct
/// or a `direct-tcpip` channel through a jump host. `jump` enables
/// ProxyJump chaining.
async fn handshake(
    params: &ConnectParams,
    jump: Option<&JumpConnection>,
) -> anyhow::Result<(Handle<ClientHandler>, ForwardedRx)> {
    // Keepalive instead of inactivity_timeout: interactive terminals stay
    // open for hours idle, but NATs get probed every 30s.
    let config = Arc::new(client::Config {
        keepalive_interval: Some(Duration::from_secs(30)),
        ..Default::default()
    });

    let connect_timeout = if params.hostkey_prompt_tx.is_some() {
        params.connect_timeout + HOSTKEY_PROMPT_GRACE
    } else {
        params.connect_timeout
    };
    let (forwarded_tx, forwarded_rx) = mpsc::unbounded_channel();
    let handler = ClientHandler {
        host: params.host.clone(),
        port: params.port,
        known_hosts_path: params.known_hosts_path.clone(),
        prompt_tx: params.hostkey_prompt_tx.clone(),
        forwarded_tx,
    };
    // Open the jump channel outside the SSH-error context so its
    // anyhow error isn't converted into russh::Error.
    let handle = if let Some(j) = jump {
        let ch = j.open_channel_to(&params.host, params.port).await?;
        tokio::time::timeout(
            connect_timeout,
            client::connect_stream(config, ch.into_stream(), handler),
        )
        .await
    } else {
        tokio::time::timeout(
            connect_timeout,
            client::connect(config, (params.host.as_str(), params.port), handler),
        )
        .await
    }
    .context("connection timed out")?
    .context("tcp/ssh handshake failed")?;
    Ok((handle, forwarded_rx))
}

async fn authenticate(
    handle: &mut Handle<ClientHandler>,
    params: &ConnectParams,
) -> anyhow::Result<()> {
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
    Ok(())
}

/// An authenticated SSH transport without a shell — a ProxyJump hop.
/// Keep it alive as long as any session is tunneled through it.
pub struct JumpConnection {
    handle: Handle<ClientHandler>,
}

impl JumpConnection {
    pub async fn connect(
        params: &ConnectParams,
        jump: Option<&JumpConnection>,
    ) -> anyhow::Result<Self> {
        let (mut handle, _forwarded_rx) = handshake(params, jump).await?;
        authenticate(&mut handle, params).await?;
        Ok(Self { handle })
    }

    /// Open a direct-tcpip channel to `host:port` through this hop.
    pub async fn open_channel_to(
        &self,
        host: &str,
        port: u16,
    ) -> anyhow::Result<Channel<client::Msg>> {
        Ok(self
            .handle
            .channel_open_direct_tcpip(host.to_string(), port as u32, "127.0.0.1", 0)
            .await?)
    }
}

impl SshSession {
    pub async fn connect(
        params: &ConnectParams,
        events: mpsc::UnboundedSender<SessionEvent>,
        jump: Option<&JumpConnection>,
    ) -> anyhow::Result<Self> {
        let (mut handle, forwarded_rx) = handshake(params, jump).await?;
        authenticate(&mut handle, params).await?;

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
            handle,
            forwarded_rx: Mutex::new(Some(forwarded_rx)),
        })
    }

    /// Start a local (-L) forward: listen on `listen_addr:listen_port` and
    /// pipe every connection to `target_host:target_port` through a
    /// direct-tcpip channel. Returns the bound port and the accept task.
    pub async fn start_local_forward(
        self: &Arc<Self>,
        listen_host: String,
        listen_port: u16,
        target_host: String,
        target_port: u16,
    ) -> anyhow::Result<Forward> {
        let listener = TcpListener::bind((listen_host.as_str(), listen_port))
            .await
            .with_context(|| format!("bind {listen_host}:{listen_port}"))?;
        let bound_port = listener.local_addr()?.port();
        let session = Arc::clone(self);
        let task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut tcp, peer)) => {
                        let (th, tp) = (target_host.clone(), target_port);
                        let sess = Arc::clone(&session);
                        tokio::spawn(async move {
                            let dest = format!("{th}:{tp}");
                            match sess
                                .handle
                                .channel_open_direct_tcpip(
                                    th,
                                    tp as u32,
                                    peer.ip().to_string(),
                                    peer.port() as u32,
                                )
                                .await
                            {
                                Ok(channel) => {
                                    let mut stream = channel.into_stream();
                                    let _ =
                                        tokio::io::copy_bidirectional(&mut tcp, &mut stream).await;
                                }
                                Err(e) => {
                                    tracing::warn!("direct-tcpip to {dest} failed: {e}");
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("forward accept failed: {e}");
                        break;
                    }
                }
            }
        });
        Ok(Forward { bound_port, task })
    }

    /// Start a dynamic (-D) SOCKS5 forward: every CONNECT request is
    /// bridged to its destination through a direct-tcpip channel.
    /// Supports the no-auth method, IPv4/domain/IPv6 targets.
    pub async fn start_socks5_forward(
        self: &Arc<Self>,
        listen_host: String,
        listen_port: u16,
    ) -> anyhow::Result<Forward> {
        let listener = TcpListener::bind((listen_host.as_str(), listen_port))
            .await
            .with_context(|| format!("bind {listen_host}:{listen_port}"))?;
        let bound_port = listener.local_addr()?.port();
        let session = Arc::clone(self);
        let task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((tcp, _)) => {
                        let sess = Arc::clone(&session);
                        tokio::spawn(async move {
                            if let Err(e) = handle_socks5_conn(tcp, &sess).await {
                                tracing::warn!("socks5 conn failed: {e:#}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("socks5 accept failed: {e}");
                        break;
                    }
                }
            }
        });
        Ok(Forward { bound_port, task })
    }

    /// Create the per-session demux for remote (-R) forwards. Only the
    /// first call succeeds.
    pub async fn start_remote_forwarder(self: &Arc<Self>) -> anyhow::Result<RemoteForwarder> {
        let rx = self
            .forwarded_rx
            .lock()
            .await
            .take()
            .context("remote forwarder already started")?;
        let routes: Arc<Mutex<std::collections::HashMap<u32, (String, u16)>>> = Default::default();
        let routes2 = Arc::clone(&routes);
        let demux = tokio::spawn(async move {
            let mut rx = rx;
            while let Some((channel, port)) = rx.recv().await {
                let route = routes2.lock().await.get(&port).cloned();
                let Some((th, tp)) = route else {
                    tracing::warn!("no -R route for remote port {port}");
                    continue;
                };
                tokio::spawn(async move {
                    match TcpStream::connect((th.as_str(), tp)).await {
                        Ok(mut tcp) => {
                            let mut stream = channel.into_stream();
                            let _ = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await;
                        }
                        Err(e) => tracing::warn!("-R connect to {th}:{tp} failed: {e}"),
                    }
                });
            }
        });
        Ok(RemoteForwarder {
            routes,
            _demux: demux,
        })
    }

    /// Ask the server to listen on `addr:port` (remote -R side).
    pub async fn request_remote_forward(&self, addr: &str, port: u16) -> anyhow::Result<u16> {
        let bound = self
            .handle
            .tcpip_forward(addr.to_string(), port as u32)
            .await
            .context("tcpip_forward denied")?;
        Ok(if port == 0 { bound as u16 } else { port })
    }

    pub async fn cancel_remote_forward(&self, addr: &str, port: u16) -> anyhow::Result<()> {
        self.handle
            .cancel_tcpip_forward(addr.to_string(), port as u32)
            .await
            .context("cancel_tcpip_forward")?;
        Ok(())
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

    /// Open an SFTP subsystem channel on this session.
    pub async fn open_sftp(&self) -> anyhow::Result<russh_sftp::client::SftpSession> {
        let channel = self.handle.channel_open_session().await?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .context("request_subsystem sftp failed")?;
        let sftp = russh_sftp::client::SftpSession::new(channel.into_stream()).await?;
        Ok(sftp)
    }
}

/// Minimal SOCKS5 (RFC 1928) no-auth CONNECT handshake, then bidirectional
/// piping into a direct-tcpip channel.
async fn handle_socks5_conn(mut tcp: TcpStream, session: &Arc<SshSession>) -> anyhow::Result<()> {
    // --- greeting: VER, NMETHODS, METHODS ---
    let mut head = [0u8; 2];
    tcp.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        bail!("not a SOCKS5 greeting");
    }
    let mut methods = vec![0u8; head[1] as usize];
    tcp.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        tcp.write_all(&[0x05, 0xFF]).await?; // no acceptable methods
        bail!("client requires auth");
    }
    tcp.write_all(&[0x05, 0x00]).await?; // choose no-auth

    // --- request: VER, CMD, RSV, ATYP, ADDR, PORT ---
    let mut req = [0u8; 4];
    tcp.read_exact(&mut req).await?;
    if req[0] != 0x05 || req[1] != 0x01 {
        socks5_reply(&mut tcp, 0x07).await.ok(); // command not supported
        bail!("only CONNECT is supported");
    }
    let (host, port) = match req[3] {
        0x01 => {
            let mut a = [0u8; 6];
            tcp.read_exact(&mut a).await?;
            (
                format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
                u16::from_be_bytes([a[4], a[5]]),
            )
        }
        0x03 => {
            let mut len = [0u8; 1];
            tcp.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize + 2];
            tcp.read_exact(&mut buf).await?;
            let n = buf.len();
            (
                String::from_utf8_lossy(&buf[..n - 2]).into_owned(),
                u16::from_be_bytes([buf[n - 2], buf[n - 1]]),
            )
        }
        0x04 => {
            let mut a = [0u8; 18];
            tcp.read_exact(&mut a).await?;
            let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&a[..16])?);
            (ip.to_string(), u16::from_be_bytes([a[16], a[17]]))
        }
        _ => bail!("unknown ATYP"),
    };

    let channel = match session
        .handle
        .channel_open_direct_tcpip(host.clone(), port as u32, "127.0.0.1", 0)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            socks5_reply(&mut tcp, 0x05).await.ok(); // connection refused
            bail!("direct-tcpip to {host}:{port} failed: {e}");
        }
    };
    socks5_reply(&mut tcp, 0x00).await?; // success
    let mut stream = channel.into_stream();
    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await;
    Ok(())
}

/// Send a minimal SOCKS5 reply bound to 0.0.0.0:0.
async fn socks5_reply(tcp: &mut TcpStream, rep: u8) -> anyhow::Result<()> {
    let mut buf = [0u8; 10];
    buf[0] = 0x05;
    buf[1] = rep;
    buf[3] = 0x01;
    tcp.write_all(&buf).await?;
    Ok(())
}
