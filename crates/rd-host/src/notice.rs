//! "Your screen is being shared" notice on the host's screen, with a Disconnect button.
//!
//! While anyone is connected, the agent runs `rd-client notice` (installed next to
//! rd-host) in the desktop session. The window connects back to the agent over loopback
//! TCP and proves itself with a one-time token from its environment. Then:
//!
//! * agent -> window: `viewers\t<label>\t<label>...` whenever the list changes
//! * window -> agent: `disconnect` when the person at the computer presses the button
//!
//! Without rd-client next to rd-host, Linux falls back to a desktop notification.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rd_core::proto::AgentEvent;

use crate::agent::EventTx;
use crate::spawn::AgentProcess;

pub const TOKEN_ENV: &str = "RD_NOTICE_TOKEN";

struct Running {
    _process: AgentProcess,
    conn: Arc<Mutex<Option<TcpStream>>>,
    last: Arc<Mutex<Vec<String>>>,
}

pub struct Notice {
    events: EventTx,
    as_console_user: bool,
    running: Option<Running>,
    /// Linux fallback: names already announced with notify-send.
    announced: Vec<String>,
}

impl Notice {
    pub fn new(events: EventTx, as_console_user: bool) -> Notice {
        Notice { events, as_console_user, running: None, announced: Vec::new() }
    }

    /// The people connected right now; an empty list closes the window.
    pub fn update(&mut self, viewers: Vec<String>) {
        if viewers.is_empty() {
            self.running = None; // kills the window
            self.announced.clear();
            return;
        }
        if self.running.is_none() {
            match self.start() {
                Ok(r) => self.running = Some(r),
                Err(e) => {
                    log::info!("connection notice unavailable: {e:#}");
                    self.fallback(&viewers);
                    return;
                }
            }
        }
        let r = self.running.as_ref().unwrap();
        *r.last.lock().unwrap() = viewers.clone();
        if let Some(c) = r.conn.lock().unwrap().as_mut() {
            let _ = c.write_all(line(&viewers).as_bytes());
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

        let conn: Arc<Mutex<Option<TcpStream>>> = Arc::default();
        let last: Arc<Mutex<Vec<String>>> = Arc::default();
        let (c2, l2, events) = (conn.clone(), last.clone(), self.events.clone());
        std::thread::Builder::new().name("notice".into()).spawn(move || {
            let Some(stream) = accept(&listener, &token) else {
                log::info!("connection notice window didn't start");
                return;
            };
            let Ok(mut writer) = stream.try_clone() else { return };
            let _ = writer.write_all(line(&l2.lock().unwrap()).as_bytes());
            *c2.lock().unwrap() = Some(writer);
            for l in BufReader::new(stream).lines() {
                match l.as_deref() {
                    Ok("disconnect") => {
                        let _ = events.send(AgentEvent::EndSessions);
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        })?;
        Ok(Running { _process: process, conn, last })
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

fn line(viewers: &[String]) -> String {
    let clean: Vec<String> = viewers.iter().map(|v| v.replace(['\t', '\n', '\r'], " ")).collect();
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
