import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";

interface HostEntry {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  authKind: "password" | "key";
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
}

let hosts: HostEntry[] = [];
let tabs: SessionTab[] = [];
let activeTab: SessionTab | null = null;
let editingHostId: string | null = null;
let passwordResolve: ((v: string | null) => void) | null = null;

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
  $("#host-modal").classList.remove("hidden");
}

function closeHostModal() {
  $("#host-modal").classList.add("hidden");
}

// --- password prompt ---

function askPassword(label: string): Promise<string | null> {
  $("#password-title").textContent = label;
  ( $("#password-form") as HTMLFormElement ).reset();
  $("#password-modal").classList.remove("hidden");
  return new Promise((resolve) => {
    passwordResolve = resolve;
    (($("#password-form") as HTMLFormElement).elements.namedItem("password") as HTMLInputElement).focus();
  });
}

function closePasswordModal(result: string | null) {
  $("#password-modal").classList.add("hidden");
  passwordResolve?.(result);
  passwordResolve = null;
}

// --- sessions & tabs ---

async function connectToHost(h: HostEntry) {
  let password: string | undefined;
  if (h.authKind === "password") {
    const p = await askPassword(`Password for ${h.username}@${h.host}`);
    if (p === null) return;
    password = p;
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
  const closeBtn = document.createElement("button");
  closeBtn.className = "close";
  closeBtn.textContent = "✕";
  tabEl.append(dot, label, closeBtn);
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
    else activateTab(tab);
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

// --- wire up UI ---

$("#btn-new-host").addEventListener("click", () => openHostModal());
$("#btn-cancel-host").addEventListener("click", closeHostModal);

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
  const pw = ((e.target as HTMLFormElement).elements.namedItem("password") as HTMLInputElement).value;
  closePasswordModal(pw);
});
$("#btn-cancel-password").addEventListener("click", () => closePasswordModal(null));

async function deleteHost(id: string) {
  hosts = await invoke<HostEntry[]>("delete_host", { hostId: id });
  renderHosts();
}

void refreshHosts();
