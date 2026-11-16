use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use russh_sftp::client::SftpSession;
use serde::{Deserialize, Serialize};
use ssh_core::{
    AuthMethod, ConnectParams, HostKeyPrompt, RemoteForwarder, SessionEvent, SshSession,
};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{mpsc, oneshot};

pub struct AppState {
    sessions: Mutex<HashMap<String, Arc<SshSession>>>,
    /// session_id -> lazily opened SFTP channel
    sftps: Arc<Mutex<HashMap<String, Arc<SftpSession>>>>,
    /// verify_id -> pending host-key decision
    verifications: Arc<Mutex<HashMap<String, oneshot::Sender<bool>>>>,
    /// forward_id -> active forward
    forwards: Arc<Mutex<HashMap<String, ActiveForward>>>,
    /// session_id -> -R demux (lazily started)
    remote_forwarders: Arc<Mutex<HashMap<String, Arc<RemoteForwarder>>>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectRequest {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub key_path: Option<String>,
    pub passphrase: Option<String>,
    #[serde(default = "default_cols")]
    pub cols: u32,
    #[serde(default = "default_rows")]
    pub rows: u32,
}

fn default_cols() -> u32 {
    80
}
fn default_rows() -> u32 {
    24
}

#[tauri::command]
async fn connect(
    app: AppHandle,
    state: State<'_, AppState>,
    req: ConnectRequest,
) -> Result<String, String> {
    let auth = match req.key_path.filter(|s| !s.is_empty()) {
        Some(key_path) => AuthMethod::PrivateKey {
            path: key_path.into(),
            passphrase: req.passphrase.filter(|s| !s.is_empty()),
        },
        None => AuthMethod::Password(req.password.unwrap_or_default()),
    };
    // Host-key verification prompts -> `hostkey-verify` events, resolved
    // by the `resolve_hostkey` command.
    let (prompt_tx, mut prompt_rx) = mpsc::unbounded_channel::<HostKeyPrompt>();
    let app2 = app.clone();
    let verifications = state.verifications.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(prompt) = prompt_rx.recv().await {
            let verify_id = uuid::Uuid::new_v4().to_string();
            if let Ok(mut map) = verifications.lock() {
                map.insert(verify_id.clone(), prompt.decision);
            } else {
                continue;
            }
            let _ = app2.emit(
                "hostkey-verify",
                serde_json::json!({
                    "verifyId": verify_id,
                    "host": prompt.host,
                    "port": prompt.port,
                    "algorithm": prompt.algorithm,
                    "fingerprint": prompt.fingerprint,
                    "changed": prompt.changed,
                }),
            );
        }
    });

    let params = ConnectParams {
        host: req.host,
        port: req.port,
        username: req.username,
        auth,
        cols: req.cols,
        rows: req.rows,
        known_hosts_path: known_hosts_path(&app).ok(),
        hostkey_prompt_tx: Some(prompt_tx),
        ..Default::default()
    };

    let (tx, mut rx) = mpsc::unbounded_channel();
    let session = SshSession::connect(&params, tx)
        .await
        .map_err(|e| format!("{e:#}"))?;

    let id = uuid::Uuid::new_v4().to_string();
    state
        .sessions
        .lock()
        .map_err(|_| "state poisoned")?
        .insert(id.clone(), Arc::new(session));

    let id2 = id.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(ev) = rx.recv().await {
            match ev {
                SessionEvent::Data(d) => {
                    let _ = app.emit(&format!("ssh-data-{id2}"), d);
                }
                SessionEvent::Eof => {
                    let _ = app.emit(&format!("ssh-status-{id2}"), "eof");
                }
                SessionEvent::ExitStatus(code) => {
                    let _ = app.emit(
                        &format!("ssh-status-{id2}"),
                        serde_json::json!({ "kind": "exit", "code": code }),
                    );
                }
                SessionEvent::Closed => {
                    let _ = app.emit(&format!("ssh-status-{id2}"), "closed");
                    break;
                }
            }
        }
    });

    Ok(id)
}

#[tauri::command]
fn resolve_hostkey(
    state: State<'_, AppState>,
    verify_id: String,
    accept: bool,
) -> Result<(), String> {
    let decision = state
        .verifications
        .lock()
        .map_err(|_| "state poisoned")?
        .remove(&verify_id);
    match decision {
        Some(tx) => tx.send(accept).map_err(|_| "connection already dropped".into()),
        None => Err("no pending verification".into()),
    }
}

#[tauri::command]
async fn write_input(
    state: State<'_, AppState>,
    session_id: String,
    data: Vec<u8>,
) -> Result<(), String> {
    let session = {
        let sessions = state.sessions.lock().map_err(|_| "state poisoned")?;
        sessions.get(&session_id).cloned()
    }
    .ok_or("no such session")?;
    session.write(&data).await.map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn resize(
    state: State<'_, AppState>,
    session_id: String,
    cols: u32,
    rows: u32,
) -> Result<(), String> {
    let session = {
        let sessions = state.sessions.lock().map_err(|_| "state poisoned")?;
        sessions.get(&session_id).cloned()
    }
    .ok_or("no such session")?;
    session
        .resize(cols, rows)
        .await
        .map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn disconnect(state: State<'_, AppState>, session_id: String) -> Result<(), String> {
    if let Ok(mut map) = state.sftps.lock() {
        map.remove(&session_id);
    }
    remove_session_forwards(&state, &session_id);
    let session = state
        .sessions
        .lock()
        .map_err(|_| "state poisoned")?
        .remove(&session_id);
    match session {
        Some(s) => s.disconnect().await.map_err(|e| format!("{e:#}")),
        None => Ok(()),
    }
}

// --- SFTP ---

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SftpEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    /// unix seconds
    pub mtime: Option<u64>,
}

async fn get_sftp(
    state: &State<'_, AppState>,
    session_id: &str,
) -> Result<Arc<SftpSession>, String> {
    if let Some(s) = state
        .sftps
        .lock()
        .map_err(|_| "state poisoned")?
        .get(session_id)
    {
        return Ok(s.clone());
    }
    let session = {
        let sessions = state.sessions.lock().map_err(|_| "state poisoned")?;
        sessions.get(session_id).cloned()
    }
    .ok_or("no such session")?;
    let sftp = Arc::new(
        session
            .open_sftp()
            .await
            .map_err(|e| format!("{e:#}"))?,
    );
    state
        .sftps
        .lock()
        .map_err(|_| "state poisoned")?
        .insert(session_id.to_string(), sftp.clone());
    Ok(sftp)
}

#[tauri::command]
async fn sftp_list(
    state: State<'_, AppState>,
    session_id: String,
    path: String,
) -> Result<Vec<SftpEntry>, String> {
    let sftp = get_sftp(&state, &session_id).await?;
    let dir = sftp
        .read_dir(path)
        .await
        .map_err(|e| e.to_string())?;
    Ok(dir
        .map(|e| {
            let meta = e.metadata();
            SftpEntry {
                name: e.file_name(),
                path: e.path(),
                is_dir: e.file_type().is_dir(),
                is_symlink: e.file_type().is_symlink(),
                size: meta.len(),
                mtime: meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs()),
            }
        })
        .collect())
}

#[tauri::command]
async fn sftp_canonicalize(
    state: State<'_, AppState>,
    session_id: String,
    path: String,
) -> Result<String, String> {
    let sftp = get_sftp(&state, &session_id).await?;
    sftp.canonicalize(path).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn sftp_download(
    state: State<'_, AppState>,
    session_id: String,
    remote_path: String,
    local_path: String,
) -> Result<u64, String> {
    let sftp = get_sftp(&state, &session_id).await?;
    let mut src = sftp.open(remote_path).await.map_err(|e| e.to_string())?;
    let mut dst = tokio::fs::File::create(local_path)
        .await
        .map_err(|e| e.to_string())?;
    tokio::io::copy(&mut src, &mut dst)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn sftp_upload(
    state: State<'_, AppState>,
    session_id: String,
    local_path: String,
    remote_path: String,
) -> Result<u64, String> {
    let sftp = get_sftp(&state, &session_id).await?;
    let mut src = tokio::fs::File::open(local_path)
        .await
        .map_err(|e| e.to_string())?;
    let mut dst = sftp.create(remote_path).await.map_err(|e| e.to_string())?;
    tokio::io::copy(&mut src, &mut dst)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn sftp_mkdir(
    state: State<'_, AppState>,
    session_id: String,
    path: String,
) -> Result<(), String> {
    let sftp = get_sftp(&state, &session_id).await?;
    sftp.create_dir(path).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn sftp_remove(
    state: State<'_, AppState>,
    session_id: String,
    path: String,
    is_dir: bool,
) -> Result<(), String> {
    let sftp = get_sftp(&state, &session_id).await?;
    if is_dir {
        sftp.remove_dir(path).await.map_err(|e| e.to_string())
    } else {
        sftp.remove_file(path).await.map_err(|e| e.to_string())
    }
}

#[tauri::command]
async fn sftp_rename(
    state: State<'_, AppState>,
    session_id: String,
    old_path: String,
    new_path: String,
) -> Result<(), String> {
    let sftp = get_sftp(&state, &session_id).await?;
    sftp.rename(old_path, new_path).await.map_err(|e| e.to_string())
}

// --- port forwarding ---

struct ActiveForward {
    session_id: String,
    kind: String,
    listen_host: String,
    listen_port: u16,
    target_host: String,
    target_port: u16,
    /// Abort handle for -L accept loops; `None` for -R entries (their work
    /// lives in the session's demux task).
    task: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardInfo {
    pub id: String,
    /// "local" | "remote"
    pub kind: String,
    /// For -L the local bind; for -R the remote listen side.
    pub listen_host: String,
    pub listen_port: u16,
    pub target_host: String,
    pub target_port: u16,
}

fn info_of(id: &str, f: &ActiveForward) -> ForwardInfo {
    ForwardInfo {
        id: id.to_string(),
        kind: f.kind.clone(),
        listen_host: f.listen_host.clone(),
        listen_port: f.listen_port,
        target_host: f.target_host.clone(),
        target_port: f.target_port,
    }
}

fn get_session(state: &State<'_, AppState>, session_id: &str) -> Result<Arc<SshSession>, String> {
    state
        .sessions
        .lock()
        .map_err(|_| "state poisoned")?
        .get(session_id)
        .cloned()
        .ok_or_else(|| "no such session".to_string())
}

#[tauri::command]
async fn forward_add_local(
    state: State<'_, AppState>,
    session_id: String,
    listen_host: String,
    listen_port: u16,
    target_host: String,
    target_port: u16,
) -> Result<ForwardInfo, String> {
    let session = get_session(&state, &session_id)?;
    let fwd = session
        .start_local_forward(
            listen_host.clone(),
            listen_port,
            target_host.clone(),
            target_port,
        )
        .await
        .map_err(|e| format!("{e:#}"))?;
    let id = uuid::Uuid::new_v4().to_string();
    let af = ActiveForward {
        session_id,
        kind: "local".into(),
        listen_host,
        listen_port: fwd.bound_port,
        target_host,
        target_port,
        task: Some(fwd.task),
    };
    let info = info_of(&id, &af);
    state
        .forwards
        .lock()
        .map_err(|_| "state poisoned")?
        .insert(id, af);
    Ok(info)
}

#[tauri::command]
async fn forward_add_remote(
    state: State<'_, AppState>,
    session_id: String,
    listen_host: String,
    listen_port: u16,
    target_host: String,
    target_port: u16,
) -> Result<ForwardInfo, String> {
    let session = get_session(&state, &session_id)?;
    // Lazily start the demux that routes accepted -R channels.
    let existing = state
        .remote_forwarders
        .lock()
        .map_err(|_| "state poisoned")?
        .get(&session_id)
        .cloned();
    let forwarder = match existing {
        Some(f) => f,
        None => {
            let f = Arc::new(
                session
                    .start_remote_forwarder()
                    .await
                    .map_err(|e| format!("{e:#}"))?,
            );
            state
                .remote_forwarders
                .lock()
                .map_err(|_| "state poisoned")?
                .insert(session_id.clone(), f.clone());
            f
        }
    };
    let bound = session
        .request_remote_forward(&listen_host, listen_port)
        .await
        .map_err(|e| format!("{e:#}"))?;
    forwarder
        .add_route(bound as u32, target_host.clone(), target_port)
        .await;
    let id = uuid::Uuid::new_v4().to_string();
    let af = ActiveForward {
        session_id,
        kind: "remote".into(),
        listen_host,
        listen_port: bound,
        target_host,
        target_port,
        task: None,
    };
    let info = info_of(&id, &af);
    state
        .forwards
        .lock()
        .map_err(|_| "state poisoned")?
        .insert(id, af);
    Ok(info)
}

#[tauri::command]
async fn forward_add_dynamic(
    state: State<'_, AppState>,
    session_id: String,
    listen_host: String,
    listen_port: u16,
) -> Result<ForwardInfo, String> {
    let session = get_session(&state, &session_id)?;
    let fwd = session
        .start_socks5_forward(listen_host.clone(), listen_port)
        .await
        .map_err(|e| format!("{e:#}"))?;
    let id = uuid::Uuid::new_v4().to_string();
    let af = ActiveForward {
        session_id,
        kind: "dynamic".into(),
        listen_host,
        listen_port: fwd.bound_port,
        target_host: String::new(),
        target_port: 0,
        task: Some(fwd.task),
    };
    let info = info_of(&id, &af);
    state
        .forwards
        .lock()
        .map_err(|_| "state poisoned")?
        .insert(id, af);
    Ok(info)
}

#[tauri::command]
async fn forward_remove(
    state: State<'_, AppState>,
    forward_id: String,
) -> Result<(), String> {
    let fwd = state
        .forwards
        .lock()
        .map_err(|_| "state poisoned")?
        .remove(&forward_id)
        .ok_or("no such forward")?;
    match fwd.task {
        Some(task) => task.abort(),
        None => {
            // -R: remove route and tell the server to stop listening.
            let forwarder = state
                .remote_forwarders
                .lock()
                .map_err(|_| "state poisoned")?
                .get(&fwd.session_id)
                .cloned();
            if let Some(f) = forwarder {
                f.remove_route(fwd.listen_port as u32).await;
            }
            if let Ok(session) = get_session(&state, &fwd.session_id) {
                let _ = session
                    .cancel_remote_forward(&fwd.listen_host, fwd.listen_port)
                    .await;
            }
        }
    }
    Ok(())
}

#[tauri::command]
fn forward_list(
    state: State<'_, AppState>,
    session_id: String,
) -> Result<Vec<ForwardInfo>, String> {
    let map = state.forwards.lock().map_err(|_| "state poisoned")?;
    Ok(map
        .iter()
        .filter(|(_, f)| f.session_id == session_id)
        .map(|(id, f)| info_of(id, f))
        .collect())
}

fn remove_session_forwards(state: &State<'_, AppState>, session_id: &str) {
    if let Ok(mut map) = state.forwards.lock() {
        let ids: Vec<String> = map
            .iter()
            .filter(|(_, f)| f.session_id == session_id)
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            if let Some(f) = map.remove(&id) {
                if let Some(t) = f.task {
                    t.abort();
                }
            }
        }
    }
    if let Ok(mut m) = state.remote_forwarders.lock() {
        m.remove(session_id);
    }
}

// --- saved hosts (passwords are never persisted) ---

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HostEntry {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    /// "password" | "key"
    pub auth_kind: String,
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default)]
    pub passphrase: Option<String>,
}

fn hosts_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_config_dir()
        .map_err(|e| e.to_string())?
        .join("hosts.json"))
}

fn known_hosts_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_config_dir()
        .map_err(|e| e.to_string())?
        .join("known_hosts"))
}

#[tauri::command]
fn list_hosts(app: AppHandle) -> Result<Vec<HostEntry>, String> {
    let path = hosts_path(&app)?;
    if !path.exists() {
        return Ok(vec![]);
    }
    let text = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

fn persist_hosts(app: &AppHandle, hosts: &[HostEntry]) -> Result<(), String> {
    let path = hosts_path(app)?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    fs::write(
        &path,
        serde_json::to_string_pretty(hosts).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

#[tauri::command]
fn save_host(app: AppHandle, mut host: HostEntry) -> Result<Vec<HostEntry>, String> {
    let mut hosts = list_hosts(app.clone())?;
    if host.id.is_empty() {
        host.id = uuid::Uuid::new_v4().to_string();
    }
    match hosts.iter_mut().find(|h| h.id == host.id) {
        Some(existing) => *existing = host,
        None => hosts.push(host),
    }
    persist_hosts(&app, &hosts)?;
    Ok(hosts)
}

#[tauri::command]
fn delete_host(app: AppHandle, host_id: String) -> Result<Vec<HostEntry>, String> {
    let mut hosts = list_hosts(app.clone())?;
    hosts.retain(|h| h.id != host_id);
    persist_hosts(&app, &hosts)?;
    Ok(hosts)
}

/// Parse `path` (default `~/.ssh/config`) and merge concrete Host blocks
/// into the saved list. Existing entries whose name matches an alias are
/// replaced; returns the new list.
#[tauri::command]
fn import_ssh_config(
    app: AppHandle,
    path: Option<String>,
) -> Result<Vec<HostEntry>, String> {
    let cfg_path = match path.filter(|s| !s.is_empty()) {
        Some(p) => ssh_core::expand_tilde(&PathBuf::from(p)),
        None => dirs_fallback_home().join(".ssh").join("config"),
    };
    let parsed = ssh_core::read_ssh_config(&cfg_path).map_err(|e| e.to_string())?;
    let mut hosts = list_hosts(app.clone())?;
    for h in parsed {
        let key_path = h.identity_file.map(|p| {
            ssh_core::expand_tilde(&PathBuf::from(&p))
                .to_string_lossy()
                .into_owned()
        });
        let entry = HostEntry {
            id: uuid::Uuid::new_v4().to_string(),
            name: h.alias.clone(),
            host: h.host_name.unwrap_or(h.alias),
            port: h.port.unwrap_or(22),
            username: h.user.unwrap_or_default(),
            auth_kind: if key_path.is_some() { "key" } else { "password" }.into(),
            key_path,
            passphrase: None,
        };
        match hosts.iter_mut().find(|e| e.name == entry.name) {
            Some(existing) => {
                let id = existing.id.clone();
                *existing = HostEntry { id, ..entry };
            }
            None => hosts.push(entry),
        }
    }
    persist_hosts(&app, &hosts)?;
    Ok(hosts)
}

fn dirs_fallback_home() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_default()
}

// --- command snippets ---

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Snippet {
    pub id: String,
    pub name: String,
    /// Sent verbatim to the terminal; `\n` submits.
    pub command: String,
}

fn snippets_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_config_dir()
        .map_err(|e| e.to_string())?
        .join("snippets.json"))
}

#[tauri::command]
fn list_snippets(app: AppHandle) -> Result<Vec<Snippet>, String> {
    let path = snippets_path(&app)?;
    if !path.exists() {
        return Ok(vec![]);
    }
    let text = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

fn persist_snippets(app: &AppHandle, items: &[Snippet]) -> Result<(), String> {
    let path = snippets_path(app)?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    fs::write(
        &path,
        serde_json::to_string_pretty(items).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

#[tauri::command]
fn save_snippet(app: AppHandle, mut snippet: Snippet) -> Result<Vec<Snippet>, String> {
    let mut items = list_snippets(app.clone())?;
    if snippet.id.is_empty() {
        snippet.id = uuid::Uuid::new_v4().to_string();
    }
    match items.iter_mut().find(|s| s.id == snippet.id) {
        Some(existing) => *existing = snippet,
        None => items.push(snippet),
    }
    persist_snippets(&app, &items)?;
    Ok(items)
}

#[tauri::command]
fn delete_snippet(app: AppHandle, snippet_id: String) -> Result<Vec<Snippet>, String> {
    let mut items = list_snippets(app.clone())?;
    items.retain(|s| s.id != snippet_id);
    persist_snippets(&app, &items)?;
    Ok(items)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt::init();
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            sessions: Mutex::new(HashMap::new()),
            sftps: Arc::new(Mutex::new(HashMap::new())),
            verifications: Arc::new(Mutex::new(HashMap::new())),
            forwards: Arc::new(Mutex::new(HashMap::new())),
            remote_forwarders: Arc::new(Mutex::new(HashMap::new())),
        })
        .invoke_handler(tauri::generate_handler![
            connect,
            write_input,
            resize,
            disconnect,
            list_hosts,
            save_host,
            delete_host,
            import_ssh_config,
            list_snippets,
            save_snippet,
            delete_snippet,
            resolve_hostkey,
            sftp_list,
            sftp_canonicalize,
            sftp_download,
            sftp_upload,
            sftp_mkdir,
            sftp_remove,
            sftp_rename,
            forward_add_local,
            forward_add_remote,
            forward_add_dynamic,
            forward_remove,
            forward_list,
        ])
        .run(tauri::generate_context!())
        .expect("error while running LiteSSH");
}
