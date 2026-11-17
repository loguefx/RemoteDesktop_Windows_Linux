//! Virtual game controllers, so a viewer's controller works in games on this computer.
//!
//! * Windows: an Xbox 360 controller through the ViGEmBus driver (install it from
//!   https://github.com/nefarius/ViGEmBus/releases; without it controllers are refused).
//! * Linux: an Xbox-style controller through `/dev/uinput` (the service runs as root).
//!
//! Each controller runs on its own thread; dropping the [`Pad`] unplugs it.

use std::sync::mpsc;

use anyhow::Result;
use rd_core::proto::GamepadState;

pub struct Pad {
    tx: mpsc::Sender<GamepadState>,
}

impl Pad {
    /// Plug in a new virtual controller.
    pub fn plug(viewer: &str) -> Result<Pad> {
        let (tx, rx) = mpsc::channel::<GamepadState>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<()>>();
        let name = viewer.to_string();
        std::thread::Builder::new().name("gamepad".into()).spawn(move || run(rx, ready_tx, name))?;
        ready_rx.recv().unwrap_or_else(|_| Err(anyhow::anyhow!("controller thread stopped")))?;
        Ok(Pad { tx })
    }

    pub fn update(&self, s: GamepadState) {
        let _ = self.tx.send(s);
    }
}

#[cfg(windows)]
fn run(rx: mpsc::Receiver<GamepadState>, ready: mpsc::Sender<Result<()>>, _name: String) {
    use vigem_client::{Client, TargetId, XButtons, XGamepad, Xbox360Wired};
    let setup = || -> Result<Xbox360Wired<Client>> {
        let client = Client::connect().map_err(|e| {
            anyhow::anyhow!("controllers need the ViGEmBus driver on this computer ({e:?}); install it from github.com/nefarius/ViGEmBus")
        })?;
        let mut pad = Xbox360Wired::new(client, TargetId::XBOX360_WIRED);
        pad.plugin().map_err(|e| anyhow::anyhow!("plug in virtual controller: {e:?}"))?;
        pad.wait_ready().map_err(|e| anyhow::anyhow!("virtual controller not ready: {e:?}"))?;
        Ok(pad)
    };
    let mut pad = match setup() {
        Ok(p) => {
            let _ = ready.send(Ok(()));
            p
        }
        Err(e) => {
            let _ = ready.send(Err(e));
            return;
        }
    };
    while let Ok(s) = rx.recv() {
        let g = XGamepad {
            buttons: XButtons { raw: s.buttons },
            left_trigger: s.lt,
            right_trigger: s.rt,
            thumb_lx: s.lx,
            thumb_ly: s.ly,
            thumb_rx: s.rx,
            thumb_ry: s.ry,
        };
        if let Err(e) = pad.update(&g) {
            log::warn!("virtual controller update failed: {e:?}");
            break;
        }
    }
    let _ = pad.unplug();
}

#[cfg(target_os = "linux")]
fn run(rx: mpsc::Receiver<GamepadState>, ready: mpsc::Sender<Result<()>>, name: String) {
    let dev = match uinput::Device::create(&name) {
        Ok(d) => {
            let _ = ready.send(Ok(()));
            d
        }
        Err(e) => {
            let _ = ready.send(Err(e));
            return;
        }
    };
    let mut last = GamepadState::default();
    while let Ok(s) = rx.recv() {
        if let Err(e) = dev.send(&last, &s) {
            log::warn!("virtual controller update failed: {e:#}");
            break;
        }
        last = s;
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
fn run(_: mpsc::Receiver<GamepadState>, ready: mpsc::Sender<Result<()>>, _: String) {
    let _ = ready.send(Err(anyhow::anyhow!("controllers aren't supported on this system")));
}

#[cfg(target_os = "linux")]
mod uinput {
    //! Minimal uinput: an Xbox-style controller with the buttons and axes the kernel's
    //! xpad driver reports, so games and SDL map it like a real one.

    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::os::fd::AsRawFd;

    use anyhow::{bail, Context, Result};
    use rd_core::proto::GamepadState;

    const EV_SYN: u16 = 0;
    const EV_KEY: u16 = 1;
    const EV_ABS: u16 = 3;
    const ABS_X: u16 = 0;
    const ABS_Y: u16 = 1;
    const ABS_Z: u16 = 2;
    const ABS_RX: u16 = 3;
    const ABS_RY: u16 = 4;
    const ABS_RZ: u16 = 5;
    const ABS_HAT0X: u16 = 16;
    const ABS_HAT0Y: u16 = 17;

    // XInput bit -> evdev button.
    const BUTTONS: [(u16, u16); 11] = [
        (0x1000, 0x130), // A -> BTN_SOUTH
        (0x2000, 0x131), // B -> BTN_EAST
        (0x4000, 0x133), // X -> BTN_NORTH (xpad order)
        (0x8000, 0x134), // Y -> BTN_WEST
        (0x0100, 0x136), // LB -> BTN_TL
        (0x0200, 0x137), // RB -> BTN_TR
        (0x0020, 0x13a), // back -> BTN_SELECT
        (0x0010, 0x13b), // start -> BTN_START
        (0x0400, 0x13c), // guide -> BTN_MODE
        (0x0040, 0x13d), // left stick -> BTN_THUMBL
        (0x0080, 0x13e), // right stick -> BTN_THUMBR
    ];

    // ioctl numbers from linux/uinput.h (_IOW('U', n, int) and _IO('U', n)).
    const UI_DEV_CREATE: libc::c_ulong = 0x5501;
    const UI_DEV_DESTROY: libc::c_ulong = 0x5502;
    const UI_SET_EVBIT: libc::c_ulong = 0x4004_5564;
    const UI_SET_KEYBIT: libc::c_ulong = 0x4004_5565;
    const UI_SET_ABSBIT: libc::c_ulong = 0x4004_5567;

    const ABS_CNT: usize = 64;

    /// `struct uinput_user_dev` (the legacy setup structure every kernel accepts).
    #[repr(C)]
    struct UserDev {
        name: [u8; 80],
        bustype: u16,
        vendor: u16,
        product: u16,
        version: u16,
        ff_effects_max: u32,
        absmax: [i32; ABS_CNT],
        absmin: [i32; ABS_CNT],
        absfuzz: [i32; ABS_CNT],
        absflat: [i32; ABS_CNT],
    }

    pub struct Device {
        f: File,
    }

    impl Device {
        pub fn create(viewer: &str) -> Result<Device> {
            let f = OpenOptions::new()
                .write(true)
                .custom_flags_nonblock()
                .open("/dev/uinput")
                .context("open /dev/uinput (is the uinput module loaded?)")?;
            let fd = f.as_raw_fd();
            let ioctl = |req: libc::c_ulong, v: libc::c_int| -> Result<()> {
                if unsafe { libc::ioctl(fd, req as _, v) } < 0 {
                    bail!("uinput ioctl: {}", std::io::Error::last_os_error());
                }
                Ok(())
            };
            ioctl(UI_SET_EVBIT, EV_KEY as i32)?;
            ioctl(UI_SET_EVBIT, EV_ABS as i32)?;
            for (_, code) in BUTTONS {
                ioctl(UI_SET_KEYBIT, code as i32)?;
            }
            for a in [ABS_X, ABS_Y, ABS_Z, ABS_RX, ABS_RY, ABS_RZ, ABS_HAT0X, ABS_HAT0Y] {
                ioctl(UI_SET_ABSBIT, a as i32)?;
            }
            let mut dev = UserDev {
                name: [0; 80],
                bustype: 0x03, // USB
                vendor: 0x045e,
                product: 0x028e, // Xbox 360 controller
                version: 0x0110,
                ff_effects_max: 0,
                absmax: [0; ABS_CNT],
                absmin: [0; ABS_CNT],
                absfuzz: [0; ABS_CNT],
                absflat: [0; ABS_CNT],
            };
            let label = format!("RD Remote Desktop controller ({viewer})");
            let n = label.len().min(79);
            dev.name[..n].copy_from_slice(&label.as_bytes()[..n]);
            for a in [ABS_X, ABS_Y, ABS_RX, ABS_RY] {
                dev.absmin[a as usize] = -32768;
                dev.absmax[a as usize] = 32767;
                dev.absfuzz[a as usize] = 16;
                dev.absflat[a as usize] = 128;
            }
            for a in [ABS_Z, ABS_RZ] {
                dev.absmax[a as usize] = 255;
            }
            for a in [ABS_HAT0X, ABS_HAT0Y] {
                dev.absmin[a as usize] = -1;
                dev.absmax[a as usize] = 1;
            }
            let bytes = unsafe { std::slice::from_raw_parts(&dev as *const UserDev as *const u8, std::mem::size_of::<UserDev>()) };
            (&f).write_all(bytes).context("set up uinput device")?;
            if unsafe { libc::ioctl(fd, UI_DEV_CREATE as _) } < 0 {
                bail!("create uinput device: {}", std::io::Error::last_os_error());
            }
            Ok(Device { f })
        }

        fn event(&self, buf: &mut Vec<u8>, kind: u16, code: u16, value: i32) {
            let ev = libc::input_event { time: libc::timeval { tv_sec: 0, tv_usec: 0 }, type_: kind, code, value };
            buf.extend_from_slice(unsafe {
                std::slice::from_raw_parts(&ev as *const libc::input_event as *const u8, std::mem::size_of::<libc::input_event>())
            });
        }

        /// Send what changed from `old` to `new`.
        pub fn send(&self, old: &GamepadState, new: &GamepadState) -> Result<()> {
            let mut buf = Vec::new();
            for (bit, code) in BUTTONS {
                if (old.buttons ^ new.buttons) & bit != 0 {
                    self.event(&mut buf, EV_KEY, code, (new.buttons & bit != 0) as i32);
                }
            }
            let hat = |b: u16, neg: u16, pos: u16| -> i32 { (b & pos != 0) as i32 - (b & neg != 0) as i32 };
            let axes = |s: &GamepadState| {
                [
                    (ABS_X, s.lx as i32),
                    (ABS_Y, -(s.ly as i32).max(-32767)), // evdev: down is positive
                    (ABS_RX, s.rx as i32),
                    (ABS_RY, -(s.ry as i32).max(-32767)),
                    (ABS_Z, s.lt as i32),
                    (ABS_RZ, s.rt as i32),
                    (ABS_HAT0X, hat(s.buttons, 0x4, 0x8)),
                    (ABS_HAT0Y, hat(s.buttons, 0x1, 0x2)),
                ]
            };
            for ((code, a), (_, b)) in axes(old).into_iter().zip(axes(new)) {
                if a != b {
                    self.event(&mut buf, EV_ABS, code, b);
                }
            }
            if buf.is_empty() {
                return Ok(());
            }
            self.event(&mut buf, EV_SYN, 0, 0);
            (&self.f).write_all(&buf).context("write controller events")?;
            Ok(())
        }
    }

    impl Drop for Device {
        fn drop(&mut self) {
            unsafe {
                libc::ioctl(self.f.as_raw_fd(), UI_DEV_DESTROY as _);
            }
        }
    }

    trait NonBlock {
        fn custom_flags_nonblock(&mut self) -> &mut Self;
    }

    impl NonBlock for OpenOptions {
        fn custom_flags_nonblock(&mut self) -> &mut Self {
            use std::os::unix::fs::OpenOptionsExt;
            self.custom_flags(libc::O_NONBLOCK)
        }
    }
}
