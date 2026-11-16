import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";

interface PasswordAnswer {
  password: string;
  remember: boolean;
}

interface HostEntry {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  authKind: "password" | "key";
  passwordSaved?: boolean;
  keyPath?: string;
  passphrase?: string;
}

interface SessionTab {
  sessionId: string;
  title: string;
  term: Terminal;
  fit: FitAddon;
  el: HTMLDivElement;
  tabEl: HTMLDivElement;
  unlisteners: UnlistenFn[];
  dead: boolean;
  sftpPanel?: HTMLDivElement;
  sftpPath?: string;
  fwdPanel?: HTMLDivElement;
}

interface Snippet {
  id: string;
  name: string;
  command: string;
}

interface SftpEntry {
  name: string;
  path: string;
  isDir: boolean;
  isSymlink: boolean;
  size: number;
  mtime?: number;
}

let hosts: HostEntry[] = [];
let snippets: Snippet[] = [];
let tabs: SessionTab[] = [];
let activeTab: SessionTab | null = null;
let editingHostId: string | null = null;
let passwordResolve: ((v: PasswordAnswer | null) => void) | null = null;
const hostkeyQueue: HostKeyVerify[] = [];

const $ = <T extends HTMLElement = HTMLElement>(sel: string) =>
  document.querySelector(sel) as T;

const encoder = new TextEncoder();

async function refreshHosts() {
  hosts = await invoke<HostEntry[]>("list_hosts");
  renderHosts();
}

function renderHosts() {
  const list = $("#host-list");
  list.innerHTML = "";
  for (const h of hosts) {
    const item = document.createElement("div");
    item.className = "host-item";
    item.innerHTML = `
      <div class="info">
        <div class="name"></div>
        <div class="addr"></div>
      </div>
      <div class="actions">
        <button data-act="edit" title="Edit">✎</button>
        <button data-act="del" title="Delete">✕</button>
      </div>`;
    item.querySelector(".name")!.textContent = h.name || h.host;
    item.querySelector(".addr")!.textContent = `${h.username}@${h.host}:${h.port}`;
    item.addEventListener("click", (e) => {
      const act = (e.target as HTMLElement).dataset.act;
      if (act === "edit") openHostModal(h);
      else if (act === "del") deleteHost(h.id);
      else void connectToHost(h);
    });
    list.appendChild(item);
  }
}

// --- host modal ---

function openHostModal(existing?: HostEntry) {
  editingHostId = existing?.id ?? null;
  const form = $("#host-form") as HTMLFormElement;
  $("#host-form-title").textContent = existing ? "Edit host" : "New host";
  (form.elements.namedItem("name") as HTMLInputElement).value = existing?.name ?? "";
  (form.elements.namedItem("host") as HTMLInputElement).value = existing?.host ?? "";
  (form.elements.namedItem("port") as HTMLInputElement).value = String(existing?.port ?? 22);
  (form.elements.namedItem("username") as HTMLInputElement).value = existing?.username ?? "";
  (form.elements.namedItem("authKind") as HTMLSelectElement).value = existing?.authKind ?? "password";
  (form.elements.namedItem("keyPath") as HTMLInputElement).value = existing?.keyPath ?? "";
  (form.elements.namedItem("passphrase") as HTMLInputElement).value = existing?.passphrase ?? "";
  form.dataset.auth = ((form as HTMLFormElement).elements.namedItem("authKind") as HTMLSelectElement).value;
  $("#btn-forget-pw").classList.toggle("hidden", !existing?.passwordSaved);
  $("#host-modal").classList.remove("hidden");
}

function closeHostModal() {
  $("#host-modal").classList.add("hidden");
}

// --- password prompt ---

function askPassword(label: string): Promise<PasswordAnswer | null> {
  $("#password-title").textContent = label;
  ( $("#password-form") as HTMLFormElement ).reset();
  $("#password-modal").classList.remove("hidden");
  return new Promise((resolve) => {
    passwordResolve = resolve;
    (($("#password-form") as HTMLFormElement).elements.namedItem("password") as HTMLInputElement).focus();
  });
}

function closePasswordModal(result: PasswordAnswer | null) {
  $("#password-modal").classList.add("hidden");
  passwordResolve?.(result);
  passwordResolve = null;
}

// --- host key verification (TOFU) ---

interface HostKeyVerify {
  verifyId: string;
  host: string;
  port: number;
  algorithm: string;
  fingerprint: string;
  changed: boolean;
}

function resolveHostkey(verifyId: string, accept: boolean) {
  void invoke("resolve_hostkey", { verifyId, accept });
}

function showHostKeyModal(v: HostKeyVerify) {
  $("#hostkey-host").textContent = `${v.host}:${v.port}`;
  $("#hostkey-algo").textContent = v.algorithm;
  $("#hostkey-fp").textContent = v.fingerprint;
  $("#hostkey-desc").textContent = v.changed
    ? "The server's host key does not match the stored one."
    : "First connection to this server — verify its fingerprint.";
  $("#hostkey-warning").classList.toggle("hidden", !v.changed);
  $("#hostkey-modal").classList.remove("hidden");

  const done = (accept: boolean) => {
    $("#hostkey-modal").classList.add("hidden");
    resolveHostkey(v.verifyId, accept);
    const next = hostkeyQueue.shift();
    if (next) showHostKeyModal(next);
  };
  $("#btn-hostkey-accept").onclick = () => done(true);
  $("#btn-hostkey-reject").onclick = () => done(false);
}

void listen<HostKeyVerify>("hostkey-verify", (ev) => {
  if (!$("#hostkey-modal").classList.contains("hidden")) {
    hostkeyQueue.push(ev.payload);
  } else {
    showHostKeyModal(ev.payload);
  }
});

// --- sessions & tabs ---

async function connectToHost(h: HostEntry) {
  let password: string | undefined;
  let remember = false;
  if (h.authKind === "password") {
    if (h.passwordSaved) {
      password =
        (await invoke<string | null>("get_host_password", { hostId: h.id })) ??
        undefined;
    }
    if (password === undefined) {
      const p = await askPassword(`Password for ${h.username}@${h.host}`);
      if (p === null) return;
      password = p.password;
      remember = p.remember;
    }
  }
  const title = h.name || `${h.username}@${h.host}`;
  const tab = createTab(title);
  setStatus(tab, "connecting…");
  try {
    const { cols, rows } = termSize(tab);
    const sessionId = await invoke<string>("connect", {
      req: {
        host: h.host,
        port: h.port,
        username: h.username,
        password,
        keyPath: h.authKind === "key" ? h.keyPath : undefined,
        passphrase: h.authKind === "key" ? h.passphrase : undefined,
        cols,
        rows,
      },
    });
    tab.sessionId = sessionId;
    wireSessionEvents(tab);
    setStatus(tab, "");
    if (remember && password) {
      try {
        await invoke("save_host_password", { hostId: h.id, password });
        h.passwordSaved = true;
      } catch {
        tab.term.write(
          "\r\n\x1b[33m[could not save password to credential store]\x1b[0m\r\n",
        );
      }
    }
  } catch (e) {
    tab.term.write(`\r\n\x1b[31m${String(e)}\x1b[0m\r\n`);
    markDead(tab);
  }
}

function termSize(tab: SessionTab) {
  return { cols: tab.term.cols || 80, rows: tab.term.rows || 24 };
}

function setStatus(tab: SessionTab, _status: string) {
  // reserved for a status indicator in the tab bar
}

function createTab(title: string): SessionTab {
  const el = document.createElement("div");
  el.className = "term-container";
  $("#terminal-area").appendChild(el);
  $("#empty-state").style.display = "none";

  const term = new Terminal({
    fontFamily: "'Cascadia Mono', 'JetBrains Mono', Consolas, monospace",
    fontSize: 13,
    cursorBlink: true,
    theme: { background: "#000000" },
    allowProposedApi: true,
  });
  const fit = new FitAddon();
  term.loadAddon(fit);
  term.open(el);

  const tabEl = document.createElement("div");
  tabEl.className = "tab";
  const dot = document.createElement("span");
  dot.className = "dot";
  const label = document.createElement("span");
  label.textContent = title;
  const sftpBtn = document.createElement("button");
  sftpBtn.className = "close";
  sftpBtn.title = "SFTP file browser";
  sftpBtn.textContent = "⇄";
  const fwdBtn = document.createElement("button");
  fwdBtn.className = "close";
  fwdBtn.title = "Port forwarding (tunnels)";
  fwdBtn.textContent = "⇒";
  const closeBtn = document.createElement("button");
  closeBtn.className = "close";
  closeBtn.textContent = "✕";
  tabEl.append(dot, label, sftpBtn, fwdBtn, closeBtn);
  $("#tab-bar").appendChild(tabEl);

  const tab: SessionTab = {
    sessionId: "",
    title,
    term,
    fit,
    el,
    tabEl,
    unlisteners: [],
    dead: false,
  };

  term.onData((data) => {
    if (tab.sessionId && !tab.dead) {
      void invoke("write_input", {
        sessionId: tab.sessionId,
        data: Array.from(encoder.encode(data)),
      });
    }
  });
  term.attachCustomKeyEventHandler((e) => {
    if (e.type === "keydown" && e.ctrlKey && e.shiftKey && e.key === "V") {
      void navigator.clipboard.readText().then((t) => {
        if (t && tab.sessionId) {
          void invoke("write_input", {
            sessionId: tab.sessionId,
            data: Array.from(encoder.encode(t)),
          });
        }
      });
      return false;
    }
    if (e.type === "keydown" && e.ctrlKey && e.shiftKey && e.key === "C") {
      const sel = term.getSelection();
      if (sel) void navigator.clipboard.writeText(sel);
      return false;
    }
    return true;
  });

  tabEl.addEventListener("click", (e) => {
    if ((e.target as HTMLElement) === closeBtn) closeTab(tab);
    else if ((e.target as HTMLElement) === sftpBtn) {
      activateTab(tab);
      void toggleSftp(tab);
    } else if ((e.target as HTMLElement) === fwdBtn) {
      activateTab(tab);
      void toggleFwd(tab);
    } else activateTab(tab);
  });
  tabEl.addEventListener("auxclick", (e) => {
    if (e.button === 1) closeTab(tab);
  });

  const observer = new ResizeObserver(() => {
    if (!tab.el.classList.contains("hidden")) {
      fit.fit();
      if (tab.sessionId && !tab.dead) {
        void invoke("resize", {
          sessionId: tab.sessionId,
          cols: term.cols,
          rows: term.rows,
        });
      }
    }
  });
  observer.observe(el);
  tab.unlisteners.push(() => observer.disconnect());

  tabs.push(tab);
  activateTab(tab);
  setTimeout(() => fit.fit(), 0);
  return tab;
}

function activateTab(tab: SessionTab) {
  activeTab = tab;
  for (const t of tabs) {
    t.el.classList.toggle("hidden", t !== tab);
    t.tabEl.classList.toggle("active", t === tab);
  }
  tab.fit.fit();
  tab.term.focus();
}

async function closeTab(tab: SessionTab) {
  if (tab.sessionId && !tab.dead) {
    void invoke("disconnect", { sessionId: tab.sessionId });
  }
  for (const u of tab.unlisteners) u();
  tab.term.dispose();
  tab.el.remove();
  tab.tabEl.remove();
  tabs = tabs.filter((t) => t !== tab);
  if (activeTab === tab) {
    activeTab = null;
    const next = tabs[tabs.length - 1];
    if (next) activateTab(next);
    else $("#empty-state").style.display = "";
  }
}

function markDead(tab: SessionTab) {
  tab.dead = true;
  tab.tabEl.classList.add("dead");
}

// --- SFTP panel ---

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 10 ? 0 : 1)} ${units[i]}`;
}

function sftpStatus(tab: SessionTab, msg: string, isErr = false) {
  const el = tab.sftpPanel?.querySelector(".sftp-status");
  if (el) {
    el.textContent = msg;
    el.classList.toggle("err", isErr);
  }
}

async function toggleSftp(tab: SessionTab) {
  if (!tab.sessionId) return;
  if (!tab.sftpPanel) {
    const panel = document.createElement("div");
    panel.className = "sftp-panel";
    panel.innerHTML = `
      <div class="sftp-toolbar">
        <button data-act="up" title="Parent dir">↑</button>
        <input class="sftp-path" spellcheck="false" />
        <button data-act="refresh" title="Refresh">⟳</button>
        <button data-act="upload" title="Upload files">⇪</button>
        <button data-act="mkdir" title="New directory">+📁</button>
      </div>
      <div class="sftp-list"></div>
      <div class="sftp-status"></div>`;
    panel.querySelector<HTMLButtonElement>('[data-act="up"]')!.onclick = () => {
      const p = tab.sftpPath ?? "/";
      const parent = p === "/" ? "/" : p.replace(/\/+$/, "").replace(/\/[^\/]*$/, "") || "/";
      void sftpList(tab, parent);
    };
    panel.querySelector<HTMLButtonElement>('[data-act="refresh"]')!.onclick = () =>
      void sftpList(tab, tab.sftpPath ?? ".");
    panel.querySelector<HTMLButtonElement>('[data-act="upload"]')!.onclick = () =>
      void sftpUpload(tab);
    panel.querySelector<HTMLButtonElement>('[data-act="mkdir"]')!.onclick = () =>
      sftpMkdirRow(tab);
    panel.querySelector<HTMLInputElement>(".sftp-path")!.addEventListener("keydown", (e) => {
      if (e.key === "Enter") void sftpList(tab, (e.target as HTMLInputElement).value);
    });
    tab.el.appendChild(panel);
    tab.sftpPanel = panel;
    // resolve the initial directory (~ on most servers)
    try {
      const home = await invoke<string>("sftp_canonicalize", {
        sessionId: tab.sessionId, path: ".",
      });
      await sftpList(tab, home);
    } catch (e) {
      sftpStatus(tab, String(e), true);
    }
  }
  tab.sftpPanel.classList.toggle("open");
  if (tab.sftpPanel.classList.contains("open") && tab.sftpPath) {
    void sftpList(tab, tab.sftpPath);
  }
}

async function sftpList(tab: SessionTab, path: string) {
  const listEl = tab.sftpPanel?.querySelector(".sftp-list");
  const pathEl = tab.sftpPanel?.querySelector<HTMLInputElement>(".sftp-path");
  if (!listEl || !pathEl) return;
  try {
    sftpStatus(tab, "loading…");
    const entries = await invoke<SftpEntry[]>("sftp_list", {
      sessionId: tab.sessionId, path,
    });
    tab.sftpPath = path;
    pathEl.value = path;
    entries.sort((a, b) => Number(b.isDir) - Number(a.isDir) || a.name.localeCompare(b.name));
    listEl.innerHTML = "";
    for (const e of entries) {
      const row = document.createElement("div");
      row.className = "sftp-row";
      row.innerHTML = `
        <span class="ico">${e.isDir ? "📁" : e.isSymlink ? "🔗" : "📄"}</span>
        <span class="fname"></span>
        <span class="fsize">${e.isDir ? "" : fmtSize(e.size)}</span>
        <button class="fdel" title="Delete">✕</button>`;
      row.querySelector(".fname")!.textContent = e.name;
      row.addEventListener("dblclick", () => {
        if (e.isDir) void sftpList(tab, e.path);
        else void sftpDownload(tab, e);
      });
      const del = row.querySelector<HTMLButtonElement>(".fdel")!;
      del.addEventListener("click", () => {
        if (del.dataset.confirm === "1") {
          del.dataset.confirm = "";
          del.classList.remove("armed");
          void sftpRemove(tab, e);
        } else {
          del.dataset.confirm = "1";
          del.classList.add("armed");
          setTimeout(() => { del.dataset.confirm = ""; del.classList.remove("armed"); }, 3000);
        }
      });
      listEl.appendChild(row);
    }
    sftpStatus(tab, `${entries.length} entries`);
  } catch (e) {
    sftpStatus(tab, String(e), true);
  }
}

function sftpMkdirRow(tab: SessionTab) {
  const listEl = tab.sftpPanel?.querySelector(".sftp-list");
  if (!listEl) return;
  const row = document.createElement("div");
  row.className = "sftp-row mkdir-row";
  row.innerHTML = `<span class="ico">📁</span><input class="fname mkdir-input" placeholder="new directory name" />`;
  listEl.prepend(row);
  const input = row.querySelector<HTMLInputElement>(".mkdir-input")!;
  input.focus();
  input.addEventListener("keydown", async (ev) => {
    if (ev.key === "Escape") row.remove();
    if (ev.key !== "Enter") return;
    const name = input.value.trim();
    if (!name) { row.remove(); return; }
    const base = (tab.sftpPath ?? "/").replace(/\/+$/, "");
    try {
      await invoke("sftp_mkdir", {
        sessionId: tab.sessionId, path: `${base}/${name}`,
      });
      await sftpList(tab, tab.sftpPath ?? "/");
    } catch (e) {
      sftpStatus(tab, String(e), true);
      row.remove();
    }
  });
  input.addEventListener("blur", () => row.remove());
}

async function sftpDownload(tab: SessionTab, entry: SftpEntry) {
  const dest = await save({ defaultPath: entry.name });
  if (!dest) return;
  try {
    sftpStatus(tab, `downloading ${entry.name}…`);
    const n = await invoke<number>("sftp_download", {
      sessionId: tab.sessionId, remotePath: entry.path, localPath: dest,
    });
    sftpStatus(tab, `saved ${fmtSize(n)} → ${dest}`);
  } catch (e) {
    sftpStatus(tab, String(e), true);
  }
}

async function sftpUpload(tab: SessionTab) {
  const sel = await open({ multiple: true, directory: false });
  if (!sel) return;
  const files = Array.isArray(sel) ? sel : [sel];
  const base = (tab.sftpPath ?? "/").replace(/\/+$/, "");
  for (const local of files) {
    const name = local.split(/[\\/]/).pop()!;
    try {
      sftpStatus(tab, `uploading ${name}…`);
      const n = await invoke<number>("sftp_upload", {
        sessionId: tab.sessionId, localPath: local, remotePath: `${base}/${name}`,
      });
      sftpStatus(tab, `uploaded ${fmtSize(n)} (${name})`);
    } catch (e) {
      sftpStatus(tab, String(e), true);
    }
  }
  await sftpList(tab, tab.sftpPath ?? "/");
}

async function sftpRemove(tab: SessionTab, entry: SftpEntry) {
  try {
    await invoke("sftp_remove", {
      sessionId: tab.sessionId, path: entry.path, isDir: entry.isDir,
    });
    await sftpList(tab, tab.sftpPath ?? "/");
  } catch (e) {
    sftpStatus(tab, String(e), true);
  }
}

// --- port forwarding panel ---

interface ForwardInfo {
  id: string;
  kind: "local" | "remote" | "dynamic";
  listenHost: string;
  listenPort: number;
  targetHost: string;
  targetPort: number;
}

function fwdStatus(tab: SessionTab, msg: string, isErr = false) {
  const el = tab.fwdPanel?.querySelector(".sftp-status");
  if (el) {
    el.textContent = msg;
    el.classList.toggle("err", isErr);
  }
}

function toggleFwd(tab: SessionTab) {
  if (!tab.sessionId) return;
  if (!tab.fwdPanel) {
    const panel = document.createElement("div");
    panel.className = "sftp-panel fwd-panel";
    panel.innerHTML = `
      <div class="fwd-form">
        <select class="fwd-kind" title="Forward type">
          <option value="local">-L local</option>
          <option value="remote">-R remote</option>
          <option value="dynamic">-D socks5</option>
        </select>
        <input class="fwd-lhost" value="127.0.0.1" placeholder="listen host" />
        <input class="fwd-lport" placeholder="listen port" inputmode="numeric" />
        <span class="fwd-arrow">→</span>
        <input class="fwd-thost" placeholder="target host" />
        <input class="fwd-tport" placeholder="target port" inputmode="numeric" />
        <button data-act="add" title="Add forward">+</button>
      </div>
      <div class="sftp-list fwd-list"></div>
      <div class="sftp-status"></div>`;
    panel.querySelector<HTMLButtonElement>('[data-act="add"]')!.onclick = () =>
      void fwdAdd(tab);
    // -D needs no target fields
    panel.querySelector<HTMLSelectElement>(".fwd-kind")!.onchange = (e) => {
      const isD = (e.target as HTMLSelectElement).value === "dynamic";
      for (const sel of [".fwd-thost", ".fwd-tport", ".fwd-arrow"]) {
        (panel.querySelector(sel) as HTMLElement).style.visibility = isD ? "hidden" : "";
      }
    };
    tab.el.appendChild(panel);
    tab.fwdPanel = panel;
    void fwdList(tab);
  }
  tab.fwdPanel.classList.toggle("open");
}

async function fwdAdd(tab: SessionTab) {
  const p = tab.fwdPanel;
  if (!p) return;
  const kind = p.querySelector<HTMLSelectElement>(".fwd-kind")!.value;
  const listenHost = p.querySelector<HTMLInputElement>(".fwd-lhost")!.value.trim() || "127.0.0.1";
  const listenPort = Number(p.querySelector<HTMLInputElement>(".fwd-lport")!.value);
  const targetHost = p.querySelector<HTMLInputElement>(".fwd-thost")!.value.trim();
  const targetPort = Number(p.querySelector<HTMLInputElement>(".fwd-tport")!.value);
  if (kind === "dynamic") {
    if (!listenPort) {
      fwdStatus(tab, "fill in listen port", true);
      return;
    }
    try {
      const info = await invoke<ForwardInfo>("forward_add_dynamic", {
        sessionId: tab.sessionId, listenHost, listenPort,
      });
      fwdStatus(tab, `-D socks5 ${info.listenHost}:${info.listenPort}`);
      await fwdList(tab);
    } catch (e) {
      fwdStatus(tab, String(e), true);
    }
    return;
  }
  if (!listenPort || !targetHost || !targetPort) {
    fwdStatus(tab, "fill in listen port, target host and port", true);
    return;
  }
  const cmd = kind === "local" ? "forward_add_local" : "forward_add_remote";
  try {
    const info = await invoke<ForwardInfo>(cmd, {
      sessionId: tab.sessionId,
      listenHost, listenPort, targetHost, targetPort,
    });
    fwdStatus(tab, `${kind === "local" ? "-L" : "-R"} :${info.listenPort} → ${targetHost}:${targetPort}`);
    await fwdList(tab);
  } catch (e) {
    fwdStatus(tab, String(e), true);
  }
}

async function fwdList(tab: SessionTab) {
  const listEl = tab.fwdPanel?.querySelector(".fwd-list");
  if (!listEl) return;
  try {
    const fwds = await invoke<ForwardInfo[]>("forward_list", {
      sessionId: tab.sessionId,
    });
    listEl.innerHTML = "";
    for (const f of fwds) {
      const row = document.createElement("div");
      row.className = "sftp-row";
      row.innerHTML = `
        <span class="ico">${f.kind === "local" ? "⇒" : f.kind === "remote" ? "⇐" : "⇶"}</span>
        <span class="fname"></span>
        <button class="fdel" title="Remove">✕</button>`;
      row.querySelector(".fname")!.textContent = f.kind === "dynamic"
        ? `-D socks5 ${f.listenHost}:${f.listenPort}`
        : `${f.kind === "local" ? "-L" : "-R"} ${f.listenHost}:${f.listenPort} → ${f.targetHost}:${f.targetPort}`;
      row.querySelector<HTMLButtonElement>(".fdel")!.onclick = async () => {
        try {
          await invoke("forward_remove", { forwardId: f.id });
          await fwdList(tab);
        } catch (e) {
          fwdStatus(tab, String(e), true);
        }
      };
      listEl.appendChild(row);
    }
    if (!fwds.length) fwdStatus(tab, "no forwards");
  } catch (e) {
    fwdStatus(tab, String(e), true);
  }
}

function wireSessionEvents(tab: SessionTab) {
  const dataEvent = `ssh-data-${tab.sessionId}`;
  const statusEvent = `ssh-status-${tab.sessionId}`;
  const p = Promise.all([
    listen<number[]>(dataEvent, (ev) => {
      tab.term.write(new Uint8Array(ev.payload));
    }),
    listen<unknown>(statusEvent, (ev) => {
      markDead(tab);
      const payload = ev.payload;
      if (typeof payload === "object" && payload !== null && "kind" in payload) {
        const code = (payload as Record<string, unknown>).code;
        tab.term.write(
          `\r\n\x1b[33m[process exited, code ${String(code)}]\x1b[0m\r\n`,
        );
      } else {
        tab.term.write("\r\n\x1b[33m[connection closed]\x1b[0m\r\n");
      }
    }),
  ]);
  void p.then((uns) => tab.unlisteners.push(...uns));
}

// --- command snippets ---

function renderSnippets() {
  const list = $("#snippet-list");
  list.innerHTML = "";
  for (const s of snippets) {
    const item = document.createElement("div");
    item.className = "host-item snippet-item";
    item.innerHTML = `
      <div class="info">
        <div class="name"></div>
        <div class="addr mono"></div>
      </div>
      <div class="actions">
        <button data-act="del" title="Delete">✕</button>
      </div>`;
    item.querySelector(".name")!.textContent = s.name;
    item.querySelector(".addr")!.textContent = s.command;
    item.addEventListener("click", (e) => {
      if ((e.target as HTMLElement).dataset.act === "del") {
        void invoke<Snippet[]>("delete_snippet", { snippetId: s.id }).then((v) => {
          snippets = v;
          renderSnippets();
        });
      } else {
        sendSnippet(s);
      }
    });
    list.appendChild(item);
  }
}

function sendSnippet(s: Snippet) {
  if (!activeTab?.sessionId || activeTab.dead) return;
  const text = s.command.endsWith("\n") ? s.command : s.command + "\n";
  void invoke("write_input", {
    sessionId: activeTab.sessionId,
    data: Array.from(encoder.encode(text)),
  });
  activeTab.term.focus();
}

async function refreshSnippets() {
  snippets = await invoke<Snippet[]>("list_snippets");
  renderSnippets();
}

// --- wire up UI ---

$("#btn-new-host").addEventListener("click", () => openHostModal());

$("#btn-import-config").addEventListener("click", async () => {
  try {
    const before = hosts.length;
    hosts = await invoke<HostEntry[]>("import_ssh_config", { path: null });
    renderHosts();
    const added = hosts.length - before;
    alert(added > 0 ? `Imported ${added} host(s) from ~/.ssh/config.` : "~/.ssh/config imported (no new hosts).");
  } catch (e) {
    alert(`Import failed: ${String(e)}`);
  }
});
$("#btn-cancel-host").addEventListener("click", closeHostModal);

$("#btn-new-snippet").addEventListener("click", () => {
  $("#snippet-form").classList.toggle("hidden");
  ($("#snippet-name") as HTMLInputElement).focus();
});

$("#btn-save-snippet").addEventListener("click", async () => {
  const name = ($("#snippet-name") as HTMLInputElement).value.trim();
  const command = ($("#snippet-command") as HTMLInputElement).value;
  if (!name || !command) return;
  snippets = await invoke<Snippet[]>("save_snippet", {
    snippet: { id: "", name, command },
  });
  renderSnippets();
  ($("#snippet-name") as HTMLInputElement).value = "";
  ($("#snippet-command") as HTMLInputElement).value = "";
  $("#snippet-form").classList.add("hidden");
});

($("#host-form") as HTMLFormElement).addEventListener("submit", (e) => {
  e.preventDefault();
  const form = e.target as HTMLFormElement;
  const host: HostEntry = {
    id: editingHostId ?? "",
    name: (form.elements.namedItem("name") as HTMLInputElement).value.trim(),
    host: (form.elements.namedItem("host") as HTMLInputElement).value.trim(),
    port: Number((form.elements.namedItem("port") as HTMLInputElement).value) || 22,
    username: (form.elements.namedItem("username") as HTMLInputElement).value.trim(),
    authKind: (form.elements.namedItem("authKind") as HTMLSelectElement).value as "password" | "key",
    passwordSaved: hosts.find((h) => h.id === editingHostId)?.passwordSaved ?? false,
    keyPath: (form.elements.namedItem("keyPath") as HTMLInputElement).value.trim() || undefined,
    passphrase: (form.elements.namedItem("passphrase") as HTMLInputElement).value || undefined,
  };
  void invoke<HostEntry[]>("save_host", { host }).then((saved) => {
    hosts = saved;
    renderHosts();
    closeHostModal();
  });
});

(($("#host-form") as HTMLFormElement).elements.namedItem("authKind") as HTMLSelectElement).addEventListener(
  "change",
  (e) => {
    ($("#host-form") as HTMLFormElement).dataset.auth = (e.target as HTMLSelectElement).value;
  },
);

$("#btn-forget-pw").addEventListener("click", () => {
  if (!editingHostId) return;
  void invoke("clear_host_password", { hostId: editingHostId }).then(() => {
    const h = hosts.find((x) => x.id === editingHostId);
    if (h) h.passwordSaved = false;
    $("#btn-forget-pw").classList.add("hidden");
  });
});

$("#btn-browse-key").addEventListener("click", () => {
  void open({ multiple: false, directory: false }).then((path) => {
    if (typeof path === "string") {
      (($("#host-form") as HTMLFormElement).elements.namedItem("keyPath") as HTMLInputElement).value =
        path;
    }
  });
});

($("#password-form") as HTMLFormElement).addEventListener("submit", (e) => {
  e.preventDefault();
  const els = (e.target as HTMLFormElement).elements;
  closePasswordModal({
    password: (els.namedItem("password") as HTMLInputElement).value,
    remember: (els.namedItem("remember") as HTMLInputElement).checked,
  });
});
$("#btn-cancel-password").addEventListener("click", () => closePasswordModal(null));

async function deleteHost(id: string) {
  hosts = await invoke<HostEntry[]>("delete_host", { hostId: id });
  renderHosts();
}

void refreshHosts();
void refreshSnippets();
