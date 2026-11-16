use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use ssh_core::{AuthMethod, ConnectParams, SessionEvent, SshSession};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::mpsc;

pub struct AppState {
    sessions: Mutex<HashMap<String, Arc<SshSession>>>,
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
    let params = ConnectParams {
        host: req.host,
        port: req.port,
        username: req.username,
        auth,
        cols: req.cols,
        rows: req.rows,
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt::init();
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            sessions: Mutex::new(HashMap::new()),
        })
        .invoke_handler(tauri::generate_handler![
            connect,
            write_input,
            resize,
            disconnect,
            list_hosts,
            save_host,
            delete_host,
        ])
        .run(tauri::generate_context!())
        .expect("error while running LiteSSH");
}
