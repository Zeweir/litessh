use std::{path::PathBuf, time::Duration};

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

    let params = ConnectParams {
        host: args.host,
        port: args.port,
        username: args.user,
        auth,
        ..Default::default()
    };

    let (tx, mut rx) = mpsc::unbounded_channel();
    let session = SshSession::connect(&params, tx).await?;
    eprintln!("[connected]");
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
