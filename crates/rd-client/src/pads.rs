//! Game controllers in gaming mode: up to four controllers plugged into this computer
//! are forwarded to the remote one, which shows them as Xbox controllers.

#[cfg(feature = "gamepads")]
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(feature = "gamepads")]
use std::time::Duration;

#[cfg(feature = "gamepads")]
use gilrs::{Axis, Button, Gilrs};
#[cfg(feature = "gamepads")]
use rd_core::proto::{GamepadState, MAX_PADS};
use rd_core::proto::ClientMsg;
use tokio::sync::mpsc::UnboundedSender;

/// Stops forwarding (and unplugs the remote controllers) when dropped.
pub struct Forwarder {
    stop: Arc<AtomicBool>,
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

pub fn start(tx: UnboundedSender<ClientMsg>) -> Forwarder {
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let _ = std::thread::Builder::new().name("gamepads".into()).spawn(move || run(tx, s2));
    Forwarder { stop }
}

#[cfg(not(feature = "gamepads"))]
fn run(_: UnboundedSender<ClientMsg>, _: Arc<AtomicBool>) {
    log::info!("this build has no game controller support");
}

#[cfg(feature = "gamepads")]
fn state(g: &gilrs::Gamepad<'_>) -> GamepadState {
    const MAP: [(Button, u16); 15] = [
        (Button::DPadUp, 0x0001),
        (Button::DPadDown, 0x0002),
        (Button::DPadLeft, 0x0004),
        (Button::DPadRight, 0x0008),
        (Button::Start, 0x0010),
        (Button::Select, 0x0020),
        (Button::LeftThumb, 0x0040),
        (Button::RightThumb, 0x0080),
        (Button::LeftTrigger, 0x0100),
        (Button::RightTrigger, 0x0200),
        (Button::Mode, 0x0400),
        (Button::South, 0x1000),
        (Button::East, 0x2000),
        (Button::West, 0x4000),
        (Button::North, 0x8000),
    ];
    let buttons = MAP.iter().filter(|(b, _)| g.is_pressed(*b)).fold(0u16, |m, (_, bit)| m | bit);
    let stick = |a: Axis| (g.value(a).clamp(-1.0, 1.0) * 32767.0) as i16;
    let trigger = |b: Button| (g.button_data(b).map(|d| d.value()).unwrap_or(0.0).clamp(0.0, 1.0) * 255.0) as u8;
    GamepadState {
        buttons,
        lt: trigger(Button::LeftTrigger2),
        rt: trigger(Button::RightTrigger2),
        lx: stick(Axis::LeftStickX),
        ly: stick(Axis::LeftStickY),
        rx: stick(Axis::RightStickX),
        ry: stick(Axis::RightStickY),
    }
}

#[cfg(feature = "gamepads")]
fn run(tx: UnboundedSender<ClientMsg>, stop: Arc<AtomicBool>) {
    let mut gilrs = match Gilrs::new() {
        Ok(g) => g,
        Err(e) => {
            log::info!("game controllers unavailable: {e}");
            return;
        }
    };
    // gilrs id -> (remote pad number, last state sent)
    let mut pads: HashMap<gilrs::GamepadId, (u8, GamepadState)> = HashMap::new();
    while !stop.load(Ordering::Relaxed) {
        let mut changed = Vec::new();
        while let Some(ev) = gilrs.next_event_blocking(Some(Duration::from_millis(50))) {
            if matches!(ev.event, gilrs::EventType::Disconnected) {
                if let Some((n, _)) = pads.remove(&ev.id) {
                    if tx.send(ClientMsg::Gamepad { pad: n, state: None }).is_err() {
                        return;
                    }
                }
                continue;
            }
            changed.push(ev.id);
            if changed.len() > 32 {
                break;
            }
        }
        for id in changed {
            if !pads.contains_key(&id) {
                let Some(free) = (0..MAX_PADS).find(|n| !pads.values().any(|(m, _)| m == n)) else { continue };
                pads.insert(id, (free, GamepadState { buttons: u16::MAX, ..Default::default() }));
            }
            let s = state(&gilrs.gamepad(id));
            let (n, last) = pads.get_mut(&id).unwrap();
            if *last != s {
                *last = s;
                if tx.send(ClientMsg::Gamepad { pad: *n, state: Some(s) }).is_err() {
                    return;
                }
            }
        }
    }
    for (n, _) in pads.into_values() {
        let _ = tx.send(ClientMsg::Gamepad { pad: n, state: None });
    }
}
