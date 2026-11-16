//! Starting the desktop agent in the right place.
//!
//! * `SpawnMode::Child` – plain child process in the daemon's own session (`rd-host run`,
//!   or a non-root Linux daemon).
//! * Windows service – the service lives in Session 0 which has no visible desktop, so the
//!   agent is launched into the *active console session* with a copy of the service's
//!   SYSTEM token (`winsta0\default`). Running as SYSTEM lets it follow the input desktop
//!   onto the lock screen / UAC prompts.
//! * Linux root daemon – find the active local graphical session via logind, borrow its
//!   environment (DISPLAY / WAYLAND_DISPLAY / XAUTHORITY / D-Bus address) and run the
//!   agent as that user, so X11 auth and the xdg-desktop-portal both work.

use std::path::PathBuf;

use anyhow::{Context, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpawnMode {
    Child,
    /// Daemon is a system service; place the agent in the interactive user session.
    UserSession,
}

pub struct AgentProcess {
    #[cfg(windows)]
    inner: AgentInner,
    #[cfg(not(windows))]
    child: std::process::Child,
}

#[cfg(windows)]
enum AgentInner {
    Child(std::process::Child),
    Handle(win::OwnedProcess),
}

impl AgentProcess {
    pub fn kill(&mut self) {
        #[cfg(windows)]
        match &mut self.inner {
            AgentInner::Child(c) => {
                let _ = c.kill();
                let _ = c.wait();
            }
            AgentInner::Handle(h) => h.kill(),
        }
        #[cfg(not(windows))]
        {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

impl Drop for AgentProcess {
    fn drop(&mut self) {
        self.kill();
    }
}

pub struct AgentArgs {
    pub exe: PathBuf,
    pub args: Vec<String>,
    pub token: String,
}

/// Start a window for the person at the computer (the "connected" notice). From the
/// Windows service the agent runs as SYSTEM, so the window is started as the signed-in
/// console user instead; elsewhere it's a plain child process (same user as the agent).
pub fn spawn_ui(exe: &std::path::Path, args: &[String], env: &[(String, String)], as_console_user: bool) -> Result<AgentProcess> {
    #[cfg(windows)]
    if as_console_user {
        return Ok(AgentProcess { inner: AgentInner::Handle(win::spawn_as_console_user(exe, args, env)?) });
    }
    let _ = as_console_user;
    let child = std::process::Command::new(exe)
        .args(args)
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .stdin(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("start {}", exe.display()))?;
    #[cfg(windows)]
    return Ok(AgentProcess { inner: AgentInner::Child(child) });
    #[cfg(not(windows))]
    return Ok(AgentProcess { child });
}

pub fn spawn(mode: SpawnMode, a: &AgentArgs) -> Result<AgentProcess> {
    match mode {
        SpawnMode::Child => {
            let child = std::process::Command::new(&a.exe)
                .args(&a.args)
                .env(crate::agent::TOKEN_ENV, &a.token)
                .spawn()
                .context("spawn agent")?;
            #[cfg(windows)]
            return Ok(AgentProcess { inner: AgentInner::Child(child) });
            #[cfg(not(windows))]
            return Ok(AgentProcess { child });
        }
        SpawnMode::UserSession => {
            #[cfg(windows)]
            return Ok(AgentProcess { inner: AgentInner::Handle(win::spawn_in_console_session(a)?) });
            #[cfg(target_os = "linux")]
            return Ok(AgentProcess { child: linux::spawn_in_graphical_session(a)? });
            #[cfg(not(any(windows, target_os = "linux")))]
            anyhow::bail!("unsupported OS");
        }
    }
}

// ====================================================================== Windows

#[cfg(windows)]
mod win {
    use anyhow::{bail, Context, Result};
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        DuplicateTokenEx, SecurityIdentification, SetTokenInformation, TokenPrimary, TokenSessionId, TOKEN_ALL_ACCESS,
    };
    use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
    use windows::Win32::System::RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken};
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, GetCurrentProcess, OpenProcessToken, TerminateProcess, WaitForSingleObject,
        CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
    };

    use super::AgentArgs;

    pub struct OwnedProcess(HANDLE);

    // A process handle can be used from any thread.
    unsafe impl Send for OwnedProcess {}

    impl OwnedProcess {
        pub fn kill(&mut self) {
            if self.0.is_invalid() {
                return;
            }
            unsafe {
                let _ = TerminateProcess(self.0, 0);
                let _ = WaitForSingleObject(self.0, 2000);
                let _ = CloseHandle(self.0);
            }
            self.0 = HANDLE::default();
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn quote(arg: &str) -> String {
        if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
            return arg.to_string();
        }
        format!("\"{}\"", arg.replace('"', "\\\""))
    }

    /// Start `exe` as the user signed in on the console, with that user's environment
    /// plus `extra`. Needs the SYSTEM token the service gives the agent.
    pub fn spawn_as_console_user(exe: &std::path::Path, args: &[String], extra: &[(String, String)]) -> Result<OwnedProcess> {
        unsafe {
            let mut token = HANDLE::default();
            WTSQueryUserToken(WTSGetActiveConsoleSessionId(), &mut token).context("nobody is signed in on the console")?;
            // The user's own environment block: UTF-16 "K=V\0" entries, ending in an empty one.
            let mut vars: Vec<String> = Vec::new();
            let mut block: *mut std::ffi::c_void = std::ptr::null_mut();
            if CreateEnvironmentBlock(&mut block, token, false).is_ok() && !block.is_null() {
                let mut p = block as *const u16;
                loop {
                    let mut len = 0;
                    while *p.add(len) != 0 {
                        len += 1;
                    }
                    if len == 0 {
                        break;
                    }
                    vars.push(String::from_utf16_lossy(std::slice::from_raw_parts(p, len)));
                    p = p.add(len + 1);
                }
                let _ = DestroyEnvironmentBlock(block);
            }
            for (k, v) in extra {
                vars.push(format!("{k}={v}"));
            }
            let mut env: Vec<u16> = Vec::new();
            for kv in vars {
                env.extend(kv.encode_utf16());
                env.push(0);
            }
            env.push(0);

            let mut cmd = std::iter::once(quote(&exe.to_string_lossy()))
                .chain(args.iter().map(|s| quote(s)))
                .collect::<Vec<_>>()
                .join(" ");
            cmd.push('\0');
            let mut cmd: Vec<u16> = cmd.encode_utf16().collect();
            let mut desktop = wide("winsta0\\default");
            let si = STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOW>() as u32,
                lpDesktop: PWSTR(desktop.as_mut_ptr()),
                ..Default::default()
            };
            let mut pi = PROCESS_INFORMATION::default();
            let r = CreateProcessAsUserW(
                token,
                None,
                PWSTR(cmd.as_mut_ptr()),
                None,
                None,
                false,
                CREATE_UNICODE_ENVIRONMENT,
                Some(env.as_ptr() as *const _),
                None,
                &si,
                &mut pi,
            );
            let _ = CloseHandle(token);
            r.context("CreateProcessAsUserW")?;
            let _ = CloseHandle(pi.hThread);
            Ok(OwnedProcess(pi.hProcess))
        }
    }

    pub fn spawn_in_console_session(a: &AgentArgs) -> Result<OwnedProcess> {
        unsafe {
            let session = WTSGetActiveConsoleSessionId();
            if session == 0xFFFF_FFFF {
                bail!("no active console session (is the machine attached to a physical/virtual console?)");
            }
            let mut own = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut own).context("OpenProcessToken")?;
            let mut token = HANDLE::default();
            let dup = DuplicateTokenEx(own, TOKEN_ALL_ACCESS, None, SecurityIdentification, TokenPrimary, &mut token);
            let _ = CloseHandle(own);
            dup.context("DuplicateTokenEx")?;
            let set = SetTokenInformation(
                token,
                TokenSessionId,
                &session as *const u32 as *const _,
                std::mem::size_of::<u32>() as u32,
            );
            if let Err(e) = set {
                let _ = CloseHandle(token);
                return Err(e).context("SetTokenInformation(TokenSessionId) - is the service running as LocalSystem?");
            }

            let mut cmd = std::iter::once(quote(&a.exe.to_string_lossy()))
                .chain(a.args.iter().map(|s| quote(s)))
                .collect::<Vec<_>>()
                .join(" ");
            cmd.push('\0');
            let mut cmd: Vec<u16> = cmd.encode_utf16().collect();

            // Environment block: our env + the one-time token. UTF-16, NUL separated, double NUL end.
            let mut env: Vec<u16> = Vec::new();
            let mut vars: Vec<(String, String)> =
                std::env::vars().filter(|(k, _)| k != crate::agent::TOKEN_ENV).collect();
            vars.push((crate::agent::TOKEN_ENV.into(), a.token.clone()));
            vars.sort_by_key(|(k, _)| k.to_uppercase());
            for (k, v) in vars {
                env.extend(format!("{k}={v}").encode_utf16());
                env.push(0);
            }
            env.push(0);

            let mut desktop = wide("winsta0\\default");
            let si = STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOW>() as u32,
                lpDesktop: PWSTR(desktop.as_mut_ptr()),
                ..Default::default()
            };
            let mut pi = PROCESS_INFORMATION::default();
            let r = CreateProcessAsUserW(
                token,
                None,
                PWSTR(cmd.as_mut_ptr()),
                None,
                None,
                false,
                CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                Some(env.as_ptr() as *const _),
                None,
                &si,
                &mut pi,
            );
            let _ = CloseHandle(token);
            r.context("CreateProcessAsUserW")?;
            let _ = CloseHandle(pi.hThread);
            log::info!("agent started in console session {session} (pid {})", pi.dwProcessId);
            Ok(OwnedProcess(pi.hProcess))
        }
    }
}

// ====================================================================== Linux

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    use anyhow::{anyhow, bail, Context, Result};

    use super::AgentArgs;

    #[derive(Debug)]
    struct GraphicalSession {
        id: String,
        uid: u32,
        kind: String,
        display: String,
        class: String,
        active: bool,
    }

    fn props(id: &str) -> Result<HashMap<String, String>> {
        let out = Command::new("loginctl")
            .args(["show-session", id, "-p", "Active", "-p", "Type", "-p", "User", "-p", "Remote", "-p", "Class", "-p", "Display", "-p", "State"])
            .output()
            .context("run loginctl")?;
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
            .collect())
    }

    fn find_session() -> Result<GraphicalSession> {
        let out = Command::new("loginctl").args(["list-sessions", "--no-legend"]).output().context("run loginctl")?;
        let mut best: Option<GraphicalSession> = None;
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let Some(id) = line.split_whitespace().next() else { continue };
            let p = props(id)?;
            let kind = p.get("Type").cloned().unwrap_or_default();
            if !(kind == "x11" || kind == "wayland") || p.get("Remote").map(String::as_str) == Some("yes") {
                continue;
            }
            let s = GraphicalSession {
                id: id.to_string(),
                uid: p.get("User").and_then(|u| u.parse().ok()).unwrap_or(u32::MAX),
                kind,
                display: p.get("Display").cloned().unwrap_or_default(),
                class: p.get("Class").cloned().unwrap_or_default(),
                active: p.get("Active").map(String::as_str) == Some("yes"),
            };
            // Prefer: active > inactive, user session > greeter.
            let score = |s: &GraphicalSession| (s.active as u8) * 2 + (s.class == "user") as u8;
            if best.as_ref().map_or(true, |b| score(&s) > score(b)) {
                best = Some(s);
            }
        }
        best.ok_or_else(|| anyhow!("no local graphical session found (is anyone logged in on the console?)"))
    }

    /// Borrow the display-related environment from a process running in that session.
    fn session_env(s: &GraphicalSession) -> HashMap<String, String> {
        const KEEP: &[&str] = &[
            "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS",
            "XDG_SESSION_TYPE", "XDG_CURRENT_DESKTOP", "XDG_SESSION_DESKTOP", "HOME", "USER", "LOGNAME", "PATH", "LANG",
        ];
        let mut best: Option<(u8, HashMap<String, String>)> = None;
        if let Ok(rd) = std::fs::read_dir("/proc") {
            for e in rd.flatten() {
                let path = e.path();
                let Ok(meta) = std::fs::metadata(&path) else { continue };
                use std::os::unix::fs::MetadataExt;
                if meta.uid() != s.uid {
                    continue;
                }
                let Ok(raw) = std::fs::read(path.join("environ")) else { continue };
                let env: HashMap<String, String> = raw
                    .split(|b| *b == 0)
                    .filter_map(|kv| std::str::from_utf8(kv).ok()?.split_once('=').map(|(k, v)| (k.into(), v.into())))
                    .collect();
                let has_display = env.contains_key("WAYLAND_DISPLAY") || env.contains_key("DISPLAY");
                if !has_display {
                    continue;
                }
                // A login screen (greeter) often has no session bus; still usable on X11.
                let score = 1
                    + 2 * env.contains_key("DBUS_SESSION_BUS_ADDRESS") as u8
                    + (env.get("XDG_SESSION_ID") == Some(&s.id)) as u8;
                if best.as_ref().map_or(true, |(b, _)| score > *b) {
                    best = Some((score, env));
                }
            }
        }
        let mut env: HashMap<String, String> =
            best.map(|(_, e)| e).unwrap_or_default().into_iter().filter(|(k, _)| KEEP.contains(&k.as_str())).collect();
        let runtime = format!("/run/user/{}", s.uid);
        env.entry("XDG_RUNTIME_DIR".into()).or_insert(runtime.clone());
        env.entry("DBUS_SESSION_BUS_ADDRESS".into()).or_insert(format!("unix:path={runtime}/bus"));
        env.entry("XDG_SESSION_TYPE".into()).or_insert(s.kind.clone());
        if !s.display.is_empty() {
            env.entry("DISPLAY".into()).or_insert(s.display.clone());
        }
        env.entry("PATH".into()).or_insert("/usr/local/bin:/usr/bin:/bin".into());
        env
    }

    fn primary_gid(uid: u32) -> Result<u32> {
        unsafe {
            let pw = libc::getpwuid(uid);
            if pw.is_null() {
                bail!("unknown uid {uid}");
            }
            Ok((*pw).pw_gid)
        }
    }

    pub fn spawn_in_graphical_session(a: &AgentArgs) -> Result<std::process::Child> {
        let s = find_session()?;
        let env = session_env(&s);
        log::info!(
            "starting agent in session {} ({}, uid {}, DISPLAY={:?}, WAYLAND_DISPLAY={:?})",
            s.id,
            s.kind,
            s.uid,
            env.get("DISPLAY"),
            env.get("WAYLAND_DISPLAY")
        );
        let gid = primary_gid(s.uid)?;
        let mut args = a.args.clone();
        if !args.iter().any(|x| x == "--backend") {
            // logind knows whether this session is X11 or Wayland.
            args.extend(["--backend".into(), s.kind.clone()]);
        }
        Command::new(&a.exe)
            .args(&args)
            .env_clear()
            .envs(&env)
            .env(crate::agent::TOKEN_ENV, &a.token)
            .uid(s.uid)
            .gid(gid)
            .spawn()
            .context("spawn agent as session user")
    }
}
