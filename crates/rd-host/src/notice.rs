//! The window on the host's screen while someone is connected or asking to connect:
//! "Your screen is being shared" with a Disconnect button, "Allow ... to connect?"
//! questions, and chat with the viewers.
//!
//! The agent runs `rd-client notice` (installed next to rd-host) in the desktop
//! session. The window connects back to the agent over loopback TCP and proves itself
//! with a one-time token from its environment. Then, one tab-separated line each:
//!
//! * agent -> window: `viewers\t<label>...`, `ask\t<id>\t<label>`, `askdone\t<id>`,
//!   `chat\t<from>\t<text>`
//! * window -> agent: `disconnect`, `allow\t<id>`, `deny\t<id>`, `chat\t<text>`
//!
//! Without rd-client next to rd-host, Linux falls back to a desktop notification (and
//! connection requests are refused, since nobody can answer them).

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rd_core::proto::AgentEvent;

use crate::agent::EventTx;
use crate::spawn::AgentProcess;

pub const TOKEN_ENV: &str = "RD_NOTICE_TOKEN";

/// What the window shows; resent in full when it (re)connects.
#[derive(Default)]
struct State {
    viewers: Vec<String>,
    asks: Vec<(u32, String)>,
    chat: Vec<(String, String)>,
    conn: Option<TcpStream>,
}

impl State {
    fn send(&mut self, line: &str) {
        if let Some(c) = self.conn.as_mut() {
            if c.write_all(line.as_bytes()).is_err() {
                self.conn = None;
            }
        }
    }

    fn snapshot(&self) -> String {
        let mut s = viewers_line(&self.viewers);
        for (id, label) in &self.asks {
            s.push_str(&format!("ask\t{id}\t{}\n", clean(label)));
        }
        for (from, text) in self.chat.iter().rev().take(50).rev() {
            s.push_str(&format!("chat\t{}\t{}\n", clean(from), clean(text)));
        }
        s
    }
}

struct Running {
    _process: AgentProcess,
}

pub struct Notice {
    events: EventTx,
    as_console_user: bool,
    running: Option<Running>,
    state: Arc<Mutex<State>>,
    /// Linux fallback: names already announced with notify-send.
    announced: Vec<String>,
}

impl Notice {
    pub fn new(events: EventTx, as_console_user: bool) -> Notice {
        Notice { events, as_console_user, running: None, state: Arc::default(), announced: Vec::new() }
    }

    /// The people connected right now.
    pub fn update(&mut self, viewers: Vec<String>) {
        {
            let mut st = self.state.lock().unwrap();
            st.viewers = viewers.clone();
            let line = viewers_line(&viewers);
            st.send(&line);
        }
        if !viewers.is_empty() && !self.ensure_running() {
            self.fallback(&viewers);
        }
        self.maybe_close();
    }

    /// Ask the person at the computer whether `label` may connect.
    pub fn ask(&mut self, id: u32, label: &str) {
        {
            let mut st = self.state.lock().unwrap();
            st.asks.push((id, label.to_string()));
            st.send(&format!("ask\t{id}\t{}\n", clean(label)));
        }
        if !self.ensure_running() {
            log::info!("can't ask about {label}: no window on this screen");
            self.answer(id, false);
        }
    }

    pub fn ask_done(&mut self, id: u32) {
        {
            let mut st = self.state.lock().unwrap();
            st.asks.retain(|(i, _)| *i != id);
            st.send(&format!("askdone\t{id}\n"));
        }
        self.maybe_close();
    }

    pub fn chat(&mut self, from: &str, text: &str) {
        let mut st = self.state.lock().unwrap();
        st.chat.push((from.to_string(), text.to_string()));
        if st.chat.len() > 200 {
            st.chat.remove(0);
        }
        st.send(&format!("chat\t{}\t{}\n", clean(from), clean(text)));
    }

    fn answer(&self, id: u32, allow: bool) {
        self.state.lock().unwrap().asks.retain(|(i, _)| *i != id);
        let _ = self.events.send(AgentEvent::Answer { id, allow });
    }

    /// Close the window once nobody is connected or waiting.
    fn maybe_close(&mut self) {
        let mut st = self.state.lock().unwrap();
        if st.viewers.is_empty() && st.asks.is_empty() {
            st.conn = None;
            st.chat.clear();
            drop(st);
            self.running = None; // kills the window
            self.announced.clear();
        }
    }

    /// Start the window if it isn't running. False if it can't be shown.
    fn ensure_running(&mut self) -> bool {
        if self.running.is_some() {
            return true;
        }
        match self.start() {
            Ok(r) => {
                self.running = Some(r);
                true
            }
            Err(e) => {
                log::info!("connection notice unavailable: {e:#}");
                false
            }
        }
    }

    fn start(&self) -> anyhow::Result<Running> {
        let exe = std::env::current_exe()?.with_file_name(if cfg!(windows) { "rd-client.exe" } else { "rd-client" });
        if !exe.exists() {
            anyhow::bail!("{} not found", exe.display());
        }
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let token = crate::db::random_token();
        let args = vec!["notice".to_string(), "--connect".into(), addr.to_string()];
        let process = crate::spawn::spawn_ui(&exe, &args, &[(TOKEN_ENV.into(), token.clone())], self.as_console_user)?;

        let (state, events) = (self.state.clone(), self.events.clone());
        std::thread::Builder::new().name("notice".into()).spawn(move || {
            let Some(stream) = accept(&listener, &token) else {
                log::info!("connection notice window didn't start");
                // Nobody can answer pending questions.
                let pending: Vec<u32> = state.lock().unwrap().asks.drain(..).map(|(i, _)| i).collect();
                for id in pending {
                    let _ = events.send(AgentEvent::Answer { id, allow: false });
                }
                return;
            };
            let Ok(mut writer) = stream.try_clone() else { return };
            {
                let mut st = state.lock().unwrap();
                let _ = writer.write_all(st.snapshot().as_bytes());
                st.conn = Some(writer);
            }
            for l in BufReader::new(stream).lines() {
                let Ok(l) = l else { break };
                let mut parts = l.splitn(2, '\t');
                match (parts.next().unwrap_or(""), parts.next()) {
                    ("disconnect", _) => {
                        let _ = events.send(AgentEvent::EndSessions);
                    }
                    (verb @ ("allow" | "deny"), Some(id)) => {
                        if let Ok(id) = id.trim().parse::<u32>() {
                            state.lock().unwrap().asks.retain(|(i, _)| *i != id);
                            let _ = events.send(AgentEvent::Answer { id, allow: verb == "allow" });
                        }
                    }
                    ("chat", Some(text)) => {
                        let text: String = text.chars().take(rd_core::proto::MAX_CHAT).collect();
                        if !text.trim().is_empty() {
                            state.lock().unwrap().chat.push(("You".into(), text.clone()));
                            let _ = events.send(AgentEvent::Chat(text));
                        }
                    }
                    _ => {}
                }
            }
        })?;
        Ok(Running { _process: process })
    }

    /// No notice window: a desktop notification per new viewer (Linux).
    fn fallback(&mut self, viewers: &[String]) {
        #[cfg(target_os = "linux")]
        for v in viewers {
            if !self.announced.contains(v) {
                let _ = std::process::Command::new("notify-send")
                    .args(["--app-name=RD Remote Desktop", "Remote desktop", &format!("{v} is connected to this computer.")])
                    .spawn();
            }
        }
        self.announced = viewers.to_vec();
    }
}

/// One field of a line: no tabs or line breaks.
fn clean(s: &str) -> String {
    s.replace(['\t', '\n', '\r'], " ")
}

fn viewers_line(viewers: &[String]) -> String {
    let clean: Vec<String> = viewers.iter().map(|v| clean(v)).collect();
    format!("viewers\t{}\n", clean.join("\t"))
}

/// Wait up to 30 s for the window to connect with the right token.
fn accept(listener: &TcpListener, token: &str) -> Option<TcpStream> {
    let deadline = Instant::now() + Duration::from_secs(30);
    listener.set_nonblocking(true).ok()?;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((s, peer)) if peer.ip().is_loopback() => {
                s.set_nonblocking(false).ok()?;
                s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
                let mut first = String::new();
                if BufReader::new(&s).read_line(&mut first).is_ok() && first.trim_end() == token {
                    s.set_read_timeout(None).ok()?;
                    return Some(s);
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => return None,
        }
    }
    None
}
