//! Keyboard codes.
//!
//! The wire format carries **Linux evdev key codes** (`linux/input-event-codes.h`):
//! * Linux/X11: X keycode = evdev + 8; the Wayland portal takes evdev directly.
//! * Windows: evdev 1..=88 equal PC/AT set-1 scan codes; the rest map via [`evdev_to_win_scancode`].

pub const KEY_NUMLOCK: u16 = 69;
pub const KEY_PAUSE: u16 = 119;

pub const BTN_LEFT: u16 = 0x110;
pub const BTN_RIGHT: u16 = 0x111;
pub const BTN_MIDDLE: u16 = 0x112;
pub const BTN_SIDE: u16 = 0x113;
pub const BTN_EXTRA: u16 = 0x114;

/// Map a set-1 scan code (with the extended flag) back to an evdev code.
pub fn win_scancode_to_evdev(sc: u16, extended: bool) -> Option<u16> {
    if !extended {
        return match sc {
            0x45 => Some(119), // Pause arrives as plain 0x45 (NumLock is extended)
            1..=88 => Some(sc),
            0x73 => Some(89),
            0x7D => Some(124),
            0x64..=0x6E => Some(183 + sc - 0x64),
            0x76 => Some(194),
            _ => None,
        };
    }
    (1..=194).find(|&c| evdev_to_win_scancode(c) == Some((sc, true)))
}

/// Map an evdev code to a set-1 scan code. Returns `(scancode, extended)`.
pub fn evdev_to_win_scancode(code: u16) -> Option<(u16, bool)> {
    Some(match code {
        // Windows reports NumLock as an extended key.
        KEY_NUMLOCK => (0x45, true),
        1..=88 => (code, false),
        89 => (0x73, false),  // KEY_RO
        96 => (0x1C, true),   // KP_ENTER
        97 => (0x1D, true),   // RIGHTCTRL
        98 => (0x35, true),   // KP_SLASH
        99 => (0x37, true),   // SYSRQ / PrintScreen
        100 => (0x38, true),  // RIGHTALT
        102 => (0x47, true),  // HOME
        103 => (0x48, true),  // UP
        104 => (0x49, true),  // PAGEUP
        105 => (0x4B, true),  // LEFT
        106 => (0x4D, true),  // RIGHT
        107 => (0x4F, true),  // END
        108 => (0x50, true),  // DOWN
        109 => (0x51, true),  // PAGEDOWN
        110 => (0x52, true),  // INSERT
        111 => (0x53, true),  // DELETE
        113 => (0x20, true),  // MUTE
        114 => (0x2E, true),  // VOLUMEDOWN
        115 => (0x30, true),  // VOLUMEUP
        124 => (0x7D, false), // YEN
        125 => (0x5B, true),  // LEFTMETA
        126 => (0x5C, true),  // RIGHTMETA
        127 => (0x5D, true),  // COMPOSE / Menu
        183..=193 => (0x64 + (code - 183), false), // F13..F23
        194 => (0x76, false), // F24
        _ => return None,
    })
}
