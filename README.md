# RD — self-hosted remote desktop for Windows and Linux

A Chrome-Remote-Desktop-style remote access tool written in Rust.

- **Host** (`rd-host`) installs as a background service on Windows or Linux, captures the
  screen and system audio, injects keyboard and mouse input, and serves clipboard sync
  and file transfer.
- **Client** (`rd-client`) is a desktop app. It has:
  - **This computer:** turn on remote access with a name and a PIN, no terminal needed
  - **My computers:** computers on your network show up by themselves; once connected, they stay
    in the list and can be reached from anywhere
  - PIN sign-in, with *don't ask again on this device*
  - the remote screen with a toolbar (it slides down from the top edge in full screen) and a
    connection badge: direct or relay, round-trip time, frames per second
  - **Wake up** for sleeping computers (Wake-on-LAN), **rename on this device**, last-connected times
  - a file panel
  - an accounts screen
  - a CLI for scripting
- **Relay** (`rd-relay`) is an optional rendezvous server. It lets you reach hosts behind NAT
  or firewalls from anywhere, without opening ports on the host. Where the NATs allow it, the two
  sides then connect **directly (peer-to-peer)** and the relay carries nothing but the setup.
- **Accounts** live in a SQLite database on the host:
  - multiple users, with admin/user roles
  - per-user *view*, *control*, *clipboard* and *files* permissions
  - the first account created is always the admin
- **Sign-in** is by PIN (4-12 digits) or password. A saved device token ("don't ask again on this
  device") signs you in automatically after that.
- **Several viewers** can share one desktop at the same time. While anyone is connected, the host's
  screen shows a small *Your screen is being shared* window naming each viewer, with a
  **Disconnect** button for the person at the computer.
- **Dynamic DNS** (optional, e.g. a free DuckDNS name) keeps a computer reachable from outside after
  the internet provider changes its home address.
- **Video** is H.264 by default, with a bitrate that adapts to the connection. On Windows the GPU's
  hardware encoder (NVIDIA, AMD or Intel) does the work when there is one. Still parts of the
  screen are then resent losslessly, so text ends up pixel-exact. A lossless-only mode is one click away.
- **Linux** supports **X11** (MIT-SHM + XTest + RandR) and **Wayland** (xdg-desktop-portal +
  PipeWire). The right one is picked for each session automatically.

## Download or build

**Ready-made downloads:** each version tag (`v0.2.0`, ...) builds Windows and Linux packages on
GitHub Actions and publishes them under **Releases**. Unzip and run `rd-client`, with `rd-host` next
to it. The app checks GitHub for a newer release when it starts and shows a *Download* link; set
`RD_NO_UPDATE_CHECK=1` to turn that off.

**Arch / CachyOS / Manjaro:** `cd packaging/arch && makepkg -si` builds and installs a package from
the latest source, with an application-menu entry.

**From source:**

```bash
cargo build --release
```

Produces `rd-host`, `rd-client` and `rd-relay` in `target/release/`.

Linux build dependencies (Debian/Ubuntu names; Fedora equivalents in brackets; Arch at the end):

```bash
sudo apt install build-essential pkg-config clang \
    libpipewire-0.3-dev \
    libasound2-dev \
    libxkbcommon-dev libgl1-mesa-dev libegl1-mesa-dev
# [gcc pkgconf clang pipewire-devel alsa-lib-devel libxkbcommon-devel mesa-libGL-devel mesa-libEGL-devel]
# Arch / CachyOS / Manjaro:
#   sudo pacman -S --needed base-devel rustup clang pkgconf pipewire alsa-lib libxkbcommon mesa
```

What each package is for:

- `libpipewire-0.3-dev`: Wayland capture on the host.
- `libasound2-dev`: client audio playback.
- `libxkbcommon-dev`, `libgl1-mesa-dev`, `libegl1-mesa-dev`: the client window.
- The client's file dialogs go through xdg-desktop-portal, so GTK isn't needed.

To build an X11-only host without PipeWire, run `cargo build --release -p rd-host --no-default-features`.
For host audio on Linux, install `pulseaudio-utils` (it provides `parec`; works with PipeWire's pulse layer too).

## Quick start (the app)

1. Put `rd-client` and `rd-host` in the same folder on each computer and open `rd-client`.
2. On a computer you want to reach, choose **Set up remote access** under **This computer**:
   - **Name:** how it appears in your other devices' list.
   - **PIN:** at least 4 digits. You'll type it when you connect from another device.
   - **Allow connections from outside this network:** asks your router to forward a port (UPnP)
     so you can connect from anywhere.
   - **Keep working when your internet address changes** (optional): a free DuckDNS name and token.
   - **Wake-on-LAN:** lets your other devices wake this computer from sleep.
   - The app is also installed for everyone (Start menu / application menu), next to the service.
   - Windows asks for administrator permission (UAC) and Linux for your password (polkit);
     the app then installs and starts the background service.
3. On another device on the same network, open `rd-client`. The computer appears under
   **My computers**. Choose **Connect**, enter the PIN, and leave
   *Don't ask again on this device* ticked to skip the PIN next time.
4. Away from home, the computer stays in the list. The app tries its local address, then the
   internet address the computer announced while you were on its network, then its relay
   (if it uses one).

**Reaching it from another network:**

- **Router:** UPnP must be on (most home routers have it on). `rd-host router-check` tells you
  whether the router answers, changing nothing.
- **Changing home IP:** the internet address is refreshed each time your device is on the same
  network as the computer. If your provider changes it while you are away, a dynamic DNS name
  still finds the computer: sign in at [duckdns.org](https://www.duckdns.org), add a name, and enter
  it with your token under *Keep working when your internet address changes*. The host checks the
  router's address every 5 minutes and updates the name when it changes. Without one, use a relay
  (below) or reconnect once from home.
- **Carrier-grade NAT** (some mobile and fibre providers share one address between customers):
  no port can be forwarded; the app says so under *This computer*. Use a relay.
- **VPN on the host:** while a VPN carries the host's internet traffic, replies to connections
  from outside leave through the VPN and fail. The app shows a note when it sees this. Allow
  local and incoming traffic outside the VPN (split tunnelling), or use a relay.

**How computers are found:** the app broadcasts a small UDP query on port 47800 on each local
network (from UDP port 47802), and hosts answer with their name, certificate fingerprint and
internet address. On Linux the installer opens 47800/udp and 47802/udp in ufw or firewalld; on a
Linux computer that only runs the app, open the answer port yourself
(`sudo ufw allow 47802/udp`) or other computers won't show up there. The app
pins that fingerprint, so later connections (from anywhere) only accept the same computer. The
very first contact trusts whatever answers on your network, like pairing a Bluetooth device;
the PIN is still needed to get in.

## Install the host from a terminal

The app runs this for you. To do it by hand (Windows: elevated PowerShell; Linux: root):

```powershell
.\target\release\rd-host.exe install
```

```bash
sudo ./target/release/rd-host install
```

The installer:

1. Copies the binary and creates a private data directory (`%ProgramData%\RDHost` or `/var/lib/rd-host`).
2. **Asks you to create the admin username and password**, plus an optional PIN. With `--owner NAME
   --pin-file FILE` (what the app uses) it creates that owner account instead, with a random password,
   and you sign in with just the PIN.
3. Generates the host's TLS certificate and prints its fingerprint.
4. Registers and starts the service: Windows SCM `rd-host`, or systemd `rd-host.service`.
5. Opens the firewall: TCP for sessions and UDP for discovery on the port.
   - **Windows:** Windows Firewall rules for `rd-host.exe`.
   - **Linux:** `ufw` or `firewalld`, if one is active.
6. On Windows, enables the `SoftwareSASGeneration` policy so viewers can send Ctrl+Alt+Del.

Options:

| Option | Default | What it does |
|---|---|---|
| `--port` | `47800` | Port for direct connections |
| `--bind` | `0.0.0.0` | Address to listen on |
| `--backend` | `auto` | Capture backend: `auto`, `x11` or `wayland` |
| `--fps` | `30` | Frame rate limit |
| `--max-viewers` | `4` | Most viewers allowed on one desktop at once |
| `--video-kbps` | `8000` | Highest H.264 bitrate per viewer, in kbit/s |
| `--video-encoder` | `auto` | `auto` uses the GPU's hardware H.264 encoder when there is one (Windows), falling back to OpenH264; `software` always uses OpenH264 |
| `--name NAME` | computer name | Name shown in the app |
| `--owner USER` + `--pin-file FILE` | – | PIN-only owner account (the file is deleted after reading) |
| `--upnp` | off | Forward the port on the router (UPnP) for access from the internet |
| `--ddns-file FILE` | – | Dynamic DNS: two lines, the name and an `https://` update URL containing `{ip}` (any provider; the app fills in DuckDNS). Deleted after reading |
| `--ddns-off` | – | Stop updating the dynamic DNS name |
| `--wake-on-lan` | off | Let the network adapters wake the computer (Windows: adapter power settings; Linux: NetworkManager wired connections) |
| `--no-app` | – | Don't install the app next to the service or add the menu entry |
| `--result-file FILE` | – | Write `ok` or `error: ...` when done (the app reads this) |
| `--relay HOST[:PORT]` | – | Also register with a relay (see below) |
| `--relay-only` | – | Accept connections only through the relay; no listening port |
| `--no-firewall` | – | Don't open firewall ports |
| `--admin-user NAME` | – | Admin username for unattended installs; the password comes from `RD_ADMIN_PASSWORD` |

`rd-host uninstall [--purge]` removes the service and closes the firewall ports, and keeps the app.
`--purge` also deletes the users and keys, the app and its menu entry. **Turn off** in the app does the same without `--purge`, so setting it up again keeps
the same certificate and your devices' saved sign-ins.

## Connect

Run `rd-client` and choose **Connect** next to a computer under **My computers**.

- **Sign in:** with the computer's PIN. *Use a username and password instead* signs in as another
  account on that computer (see *Users and permissions*). Leave *Don't ask again on this device*
  on, and next time the app signs you in automatically.
- **Menu (...) next to a computer:** *Wake up* (when it's asleep), *Rename on this device*, *Manage accounts*,
  *Sign out on this device*, *Remove from my computers*.
- **Wake up** sends a Wake-on-LAN packet to the hardware addresses the computer announced. It works
  from the same network as the computer, and needs Wake-on-LAN on in its firmware (BIOS/UEFI) too.
  On Windows, *fast startup* can stop a computer that is shut down (not asleep) from waking.
- **By address:** `rd-client connect 192.168.1.20:47800` or `rd-client connect 482-913-077@relay.example.com`
  opens the app connected to an address. The first time, it shows the host's certificate
  fingerprint to compare with `rd-host info` on that computer; after that it is pinned (like SSH).

In a session:

- **Mouse and keyboard** go to the remote computer while the pointer is over the picture. Physical keys are sent, so the remote keyboard layout applies.
- **Toolbar:**
  - **Picture** mode:
    - **Smooth** (H.264, the default) is best for video, scrolling and slow connections. The current bitrate is shown next to it.
    - **Sharp** sends lossless tiles only: pixel-exact, but it needs a fast link (roughly 10+ Mbit/s while the screen moves).
    - The choice is remembered.
  - display picker (with more than one monitor)
  - **Ctrl+Alt+Del**
  - **Sound** on/off
  - **Files**
  - **Full screen**: move the pointer to the top edge to bring the toolbar back; F11 leaves
  - **Disconnect**
  - who else is connected
  - **Connection badge:** *Direct · this network*, *Direct · internet*, *Peer-to-peer* or *Relay*,
    with the round-trip time and frames per second
- **Session ended:** *Reconnect* tries again with the saved sign-in (for example after the remote
  computer went from its login screen to the desktop).
- **Clipboard:** text and images (screenshots, copied pictures) sync both ways automatically, if your account has the clipboard permission. Images up to 8K resolution are sent as PNG.
- **Copying files:** copy files or folders in Explorer or your file manager on one side and paste them on the other. This needs both the clipboard and files permissions.
  - **How:** copied files are sent along with their contents. The other side saves them in a temporary `rd-clipboard` folder and pastes from there.
  - **Size limit:** up to 32 MiB and 256 files and folders per copy. Use the Files panel for anything bigger.
- **Files panel:**
  - browse the remote user's files and download them;
  - upload with *Upload a file…*, or drop files onto the window;
  - uploads land in the remote user's **Downloads** folder and never overwrite an existing file.

## Reach a computer from anywhere (relay)

Run the relay on any machine both sides can reach. A small VPS is enough. Open its port for both **TCP and UDP**:

```bash
rd-relay --bind 0.0.0.0:47801 --state /var/lib/rd-relay/hosts.json --registration-key SOME-LONG-SECRET
```

On each host:

```bash
sudo rd-host relay set relay.example.com --key SOME-LONG-SECRET   # add --relay-only to close the direct port
sudo systemctl restart rd-host        # Windows: Restart-Service rd-host
rd-host relay show                    # prints this computer's id, e.g. 482-913-077
```

Then connect to `482-913-077@relay.example.com`.

**Peer-to-peer:**

- **How it works:** each side learns its public addresses (IPv4 and IPv6) from the relay's UDP port, and the two exchange addresses through the relay. Both send UDP packets toward each other to open their NATs, and the client tries a direct QUIC connection for up to 3 seconds.
- **When it works:** usually across home and office routers, and directly over IPv6 when both sides have it.
- **When it doesn't:** if both sides are behind strict ("symmetric") or carrier-grade NAT, the same QUIC connection runs *through* the relay's UDP port instead. If UDP is blocked altogether, the session stays on the relay's TCP connection.
- **Which path you got:** the window title says *peer-to-peer*, *relayed (UDP)* or *via relay*.
- **Same security either way:** the same pinned end-to-end TLS session and sign-in run inside both paths.
- **Turning it off:** on a host, `rd-host relay set ADDR --no-p2p` always uses the relay. On a client, set `RD_NO_P2P=1`. On the relay, `--no-udp-relay` stops it forwarding UDP, so failed direct attempts fall back to TCP.
- **Windows firewall:** the installer adds a UDP rule for `rd-host.exe`, unless you pass `--no-firewall`.

- **Hosts connect outward**, so nothing needs a port forward on the host side.
- **The relay can't read or change sessions.** It only joins two TCP streams or forwards encrypted UDP datagrams unchanged, and it never takes part in direct ones. The TLS session runs end-to-end between client and host, and the client pins the host's certificate.
- **Host ids are claimed on first use** with a secret the relay stores hashed. `--registration-key` stops strangers from registering their own hosts on your relay.

Example systemd unit for the relay:

```ini
[Service]
ExecStart=/usr/local/bin/rd-relay --bind 0.0.0.0:47801 --state /var/lib/rd-relay/hosts.json
Environment=RD_RELAY_KEY=SOME-LONG-SECRET
StateDirectory=rd-relay
DynamicUser=yes
Restart=on-failure
[Install]
WantedBy=multi-user.target
```

## Users and permissions

In the app, choose **Accounts** on a saved computer.

- **Admins** can add users, change roles, tick permissions, reset passwords, disable or remove accounts, and revoke remembered devices.
- **Everyone** can change their own password and PIN, and manage their own devices.

The same works from the command line:

```bash
rd-client users my-pc list
rd-client users my-pc add bob --perms view,clipboard     # full | view-only | none | view,control,clipboard,files
rd-client users my-pc perms bob full
rd-client account my-pc set-pin
```

Or locally on the host, as Administrator/root:

- `rd-host user add|list|remove|passwd|pin|role|perms|disable|enable|unlock`
- `rd-host devices list|revoke`

| Permission | Allows |
|---|---|
| `view` | See the screen and hear the sound |
| `control` | Keyboard and mouse, Ctrl+Alt+Del, switching displays |
| `clipboard` | Two-way clipboard sync (text and images; copying files also needs `files`) |
| `files` | Browse, download and upload files as the signed-in desktop user |

Admins always have all four. When a v1 database is upgraded, accounts keep what they could do before:

- clipboard access is granted only to accounts that already had control;
- file access is off for everyone until an admin grants it.

**Security behaviour:**

- **Stored secrets:** passwords and PINs are kept as Argon2id hashes, and device tokens as SHA-256 hashes.
- **Lockouts:** five failed sign-ins lock an account (5 min, doubling up to 1 h). Ten failures from one IP block that IP for 10 min.
- **Short PINs:** after 10 wrong PINs in a row the PIN is switched off until it is set again on that
  computer (*Change name or PIN* in the app). Even a 4-digit PIN therefore gives a stranger at most a
  0.1% chance.
- **Remembered devices** aren't affected by lockouts, so someone guessing PINs can't lock you out of
  your own devices.
- **Admin safety:** the last active admin can't be removed, demoted or disabled.
- **Files on a Windows service install:** file access impersonates the signed-in console user. The service never reads or writes files as SYSTEM, and with nobody signed in, file transfer is refused.
- **Audit log:** every sign-in and admin action is recorded (`rd-host info` shows the latest entries).
- **Who is connected:** the host shows a notice window with each viewer's account and device while a
  session is open; *Disconnect* there ends every session at once (logged in the audit log). On Linux,
  without the app installed next to rd-host, a desktop notification is shown instead.

## Diagnostics

```bash
rd-host info                               # settings, fingerprint, relay id, recent activity
rd-host router-check                       # does the router do UPnP, and what is its internet address
rd-client find                             # computers on this network that have remote access on
rd-host snapshot test.bmp [--display 1]    # list displays and capture one frame locally
rd-host run                                # foreground daemon, no service (dev/testing)
rd-client check my-pc --list --audio-seconds 3 --clipboard hi --upload f.txt --download REMOTE LOCAL
rd-client check my-pc --codec h264 --measure 10                      # frames, MB and Mbit/s over 10 s (tiles | h264 | h264:KBPS)
rd-client check my-pc --clipboard-image pic.png                     # put an image on the remote clipboard
rd-client check my-pc --hold 10 --save-clipboard-image got.png      # save an image copied remotely
rd-client check my-pc --clipboard-files a.txt folder                # copy files to the remote clipboard
rd-client snapshot my-pc out.bmp           # fetch one remote frame without a window
```

Logs: Windows `%ProgramData%\RDHost\logs\`; Linux `journalctl -u rd-host`.
Set `RUST_LOG=debug` for more detail.

## Platform notes

- **Windows:** the service runs as LocalSystem and starts the capture agent in the active console session.
  - The lock screen, sign-in screen and UAC prompts work.
  - Ctrl+Alt+Del uses `SendSAS`.
  - Audio comes from WASAPI loopback of the default output device.
- **Linux X11:** works for any X session, including X11 login greeters. Each RandR monitor is a selectable display.
  - **Tested on Ubuntu 24.04** under Xvfb: capture, XTest input, clipboard (text and files), files and the systemd install, from both the Linux and the Windows client.
  - **Clipboard after disconnect:** text copied in from a viewer stays on the host's clipboard after it disconnects only if the desktop runs a clipboard manager (GNOME, KDE and most others do), because X11 keeps clipboard contents in the owning process.
- **Linux Wayland:** goes through the xdg-desktop-portal (GNOME 43+, KDE Plasma 5.27+, and others with a RemoteDesktop portal).
  - **First session:** a permission dialog appears on the host's own screen and must be approved locally once. Tick every monitor you want to be able to switch between.
  - **After that:** sessions start unattended.
  - **Login screen:** a machine sitting at a Wayland login screen (nobody signed in) can't be captured.
    With an X11 login screen (SDDM's default) the agent uses the greeter's display.
    When someone signs in, the session restarts; choose *Reconnect*.
  - **Testing so far:** the Wayland/PipeWire path builds and is unit-tested, but hasn't been run against a real GNOME or KDE session yet.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how the pieces fit together.
