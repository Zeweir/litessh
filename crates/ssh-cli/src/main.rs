use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::Result;
use clap::Parser;
use ssh_core::{AuthMethod, ConnectParams, SessionEvent, SshSession};
use tokio::sync::mpsc;

/// Smoke test: open a PTY shell, send a command, print everything until close.
#[derive(Parser)]
struct Args {
    #[arg(long)]
    host: String,
    #[arg(long, default_value_t = 22)]
    port: u16,
    #[arg(long)]
    user: String,
    #[arg(long)]
    password: Option<String>,
    #[arg(long)]
    key: Option<PathBuf>,
    /// Command to type into the shell after connect.
    #[arg(long, default_value = "echo litessh-ok; exit\n")]
    cmd: String,
    #[arg(long, default_value_t = 15)]
    timeout_secs: u64,
    /// known_hosts file for server-key verification (TOFU).
    #[arg(long, default_value = "~/.ssh/known_hosts")]
    known_hosts: PathBuf,
    /// Skip the interactive prompt and trust a new host key.
    /// Changed keys still require a manual `yes`.
    #[arg(long)]
    yes: bool,
    /// After connecting, list this remote directory over SFTP and exit.
    #[arg(long)]
    sftp_ls: Option<String>,
    /// Local forward spec `listen_port:target_host:target_port`; binds
    /// 127.0.0.1 and prints the bound port, then keeps running until
    /// timeout. Repeatable.
    #[arg(long = "fwd-l")]
    fwd_local: Vec<String>,
    /// Remote forward spec `remote_port:target_host:target_port`.
    /// Repeatable.
    #[arg(long = "fwd-r")]
    fwd_remote: Vec<String>,
    /// Dynamic SOCKS5 forward listen port (binds 127.0.0.1). Repeatable.
    #[arg(long = "fwd-d")]
    fwd_dynamic: Vec<u16>,
}

fn parse_fwd(spec: &str) -> Result<(u16, String, u16)> {
    let parts: Vec<&str> = spec.rsplitn(3, ':').collect();
    if parts.len() != 3 {
        anyhow::bail!("bad forward spec {spec:?}, want listen:host:port");
    }
    Ok((parts[2].parse()?, parts[1].to_string(), parts[0].parse()?))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let auth = if let Some(key) = args.key {
        AuthMethod::PrivateKey {
            path: key,
            passphrase: None,
        }
    } else {
        AuthMethod::Password(args.password.unwrap_or_default())
    };

    let (prompt_tx, mut prompt_rx) = mpsc::unbounded_channel::<ssh_core::HostKeyPrompt>();
    let auto_accept = args.yes;
    tokio::spawn(async move {
        while let Some(prompt) = prompt_rx.recv().await {
            let tag = if prompt.changed { "CHANGED" } else { "new" };
            eprintln!(
                "[hostkey {tag}] {}:{} {} {}",
                prompt.host, prompt.port, prompt.algorithm, prompt.fingerprint
            );
            let accept = if auto_accept && !prompt.changed {
                eprintln!("[hostkey] auto-accepted");
                true
            } else {
                eprint!("Trust this host key? [y/N] ");
                let answer = tokio::task::spawn_blocking(|| {
                    let mut line = String::new();
                    let _ = std::io::stdin().read_line(&mut line);
                    line
                })
                .await
                .unwrap_or_default();
                answer.trim().eq_ignore_ascii_case("y")
            };
            let _ = prompt.decision.send(accept);
        }
    });

    let params = ConnectParams {
        host: args.host,
        port: args.port,
        username: args.user,
        auth,
        known_hosts_path: Some(ssh_core::expand_tilde(&args.known_hosts)),
        hostkey_prompt_tx: Some(prompt_tx),
        ..Default::default()
    };

    let (tx, mut rx) = mpsc::unbounded_channel();
    let session = Arc::new(SshSession::connect(&params, tx, None).await?);
    eprintln!("[connected]");

    if let Some(dir) = args.sftp_ls {
        let sftp = session.open_sftp().await?;
        for e in sftp.read_dir(dir).await? {
            let m = e.metadata();
            println!(
                "{}\t{}\t{}",
                if e.file_type().is_dir() { "d" } else { "-" },
                m.len(),
                e.path(),
            );
        }
        session.disconnect().await.ok();
        return Ok(());
    }

    for spec in &args.fwd_local {
        let (lp, th, tp) = parse_fwd(spec)?;
        let f = session
            .start_local_forward("127.0.0.1".into(), lp, th, tp)
            .await?;
        eprintln!("[fwd-l] 127.0.0.1:{} ready", f.bound_port);
    }
    if !args.fwd_remote.is_empty() {
        let forwarder = session.start_remote_forwarder().await?;
        for spec in &args.fwd_remote {
            let (rp, th, tp) = parse_fwd(spec)?;
            let bound = session.request_remote_forward("127.0.0.1", rp).await?;
            forwarder.add_route(bound as u32, th, tp).await;
            eprintln!("[fwd-r] remote 127.0.0.1:{bound} ready");
        }
    }

    for lp in &args.fwd_dynamic {
        let f = session
            .start_socks5_forward("127.0.0.1".into(), *lp)
            .await?;
        eprintln!("[fwd-d] socks5 127.0.0.1:{} ready", f.bound_port);
    }

    session.write(args.cmd.as_bytes()).await?;

    let deadline = tokio::time::sleep(Duration::from_secs(args.timeout_secs));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => {
                eprintln!("[timeout]");
                break;
            }
            ev = rx.recv() => match ev {
                Some(SessionEvent::Data(d)) => {
                    print!("{}", String::from_utf8_lossy(&d));
                }
                Some(other) => {
                    eprintln!("[event: {other:?}]");
                    if matches!(other, SessionEvent::Closed) { break; }
                }
                None => break,
            },
        }
    }
    session.disconnect().await.ok();
    Ok(())
}
