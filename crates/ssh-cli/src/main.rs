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

    let (prompt_tx, mut prompt_rx) =
        mpsc::unbounded_channel::<ssh_core::HostKeyPrompt>();
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
    let session = SshSession::connect(&params, tx).await?;
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
