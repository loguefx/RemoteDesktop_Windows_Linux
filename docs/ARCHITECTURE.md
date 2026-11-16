# Architecture

```
                      (optional) rd-relay  -- rendezvous: address probe + QUIC forwarding (UDP), splices TCP;
                         ^            ^          sees only ciphertext
                         |            | outbound control + data connections
                         +-- direct QUIC (peer-to-peer, IPv4/IPv6) when the NATs allow it --+
 rd-client --TLS (pinned cert, end to end)--> rd-host service --loopback + one-time token--> rd-host agent
 (GUI / CLI)                                  (network, auth, SQLite,                        (capture, encode, input,
                                               tile canvas, fan-out)                          clipboard, audio, files)
                                              Session 0 / root                               user's desktop session
```

## Crates

| Crate         | Role |
|---------------|------|
| `rd-core`     | Wire protocol v5 (`proto`), framing, TLS helpers, peer-to-peer QUIC transport (`p2p`), tile codec, H.264 encoder/decoder (OpenH264, plus Media Foundation hardware encoding on Windows in `video_mf`), IMA-ADPCM audio, clipboard sync worker (text, PNG images, files), relay protocol and targets, LAN discovery messages (`discovery`), key codes |
| `rd-platform` | `Capturer` (with multi-monitor) + `InputInjector` traits; Windows, X11 and Wayland backends |
| `rd-host`     | Service/daemon (auth, accounts, desk fan-out, relay link, discovery answers and router port mapping in `reach`), desktop agent (capture, input, clipboard, audio, files), install/CLI |
| `rd-client`   | egui/OpenGL app (this computer + my computers, remote-access setup, PIN sign-in, session view, file panel, accounts), network scan (`discover`), elevated setup (`setup`), audio playback, CLI |
| `rd-relay`    | Rendezvous relay |

## Service and agent

A Windows service runs in Session 0, which can't see the user's desktop. A systemd system
service has no X or Wayland session either. So the service handles authentication, the
database and networking, and only launches an **agent** inside the interactive session
when a viewer connects:

- **Windows:** `WTSGetActiveConsoleSessionId` → duplicate the service's SYSTEM token →
  `SetTokenInformation(TokenSessionId)` → `CreateProcessAsUser` on `winsta0\default`.
  - **Lock screen and UAC:** because the agent is SYSTEM, it can follow the input desktop onto the Winlogon desktop.
  - **Files:** file operations impersonate the console user (`WTSQueryUserToken` + `ImpersonateLoggedOnUser`), so they never run as SYSTEM.
- **Linux:** logind finds the active local `x11`/`wayland` session. The daemon copies the
  display and D-Bus environment from one of that user's processes, then runs the agent as
  that user.

The agent connects back over `127.0.0.1` with a random token passed in its environment.

## Finding computers and setting them up from the app

The app works like Chrome Remote Desktop without an account server: computers find each
other on the local network, and the app remembers how to reach them afterwards.

**Setting up this computer** (`rd-client/src/setup.rs`):

1. The app writes the PIN to a private temporary file and runs `rd-host install --name N
   --owner USER --pin-file F [--upnp] --result-file R` with administrator rights:
   - **Windows:** `Start-Process -Verb RunAs` (a UAC prompt), started through PowerShell's
     `-EncodedCommand` so no argument needs shell quoting.
   - **Linux:** `pkexec` (the desktop's polkit password dialog).
2. The installer creates the **owner** account (admin, random password) with that PIN, saves
   `name`, `owner` and `upnp` in the settings table, deletes the PIN file, and writes `ok`
   or the error to the result file, because the output of an elevated process can't be read.
3. *Turn off* runs `rd-host uninstall --result-file R`. Accounts and the certificate are
   kept, so setting it up again keeps the computer's identity and its devices' sign-ins.

**PIN-only sign-in:** a `ClientHello` with an empty username signs in as the owner.

**Discovery** (`rd_core::discovery`, `rd-host/src/reach.rs`, `rd-client/src/discover.rs`):

- **Query:** the app sends a 600-byte `RDQ1` datagram to UDP 47800 at each local network's
  broadcast address, `255.255.255.255` and `127.0.0.1`, twice over 1.2 s, every 5 s while
  the home screen is open.
- **Answer:** the host replies to the sender with `RDA1` + postcard `Announce { name,
  fingerprint, port, protocol, public, public_note, relay }`.
  - The reply is never larger than the query.
  - Only private, link-local and loopback senders get answers, at most 50 a second.
  - Windows' firewall lets unicast replies to a broadcast through without a rule. The host's
    UDP rule (Windows) or ufw/firewalld rule (Linux) lets the queries in.
- **This computer:** an answer from loopback or one of the app's own addresses.
- **Saving:** a computer is saved (keyed by fingerprint) the first time you choose Connect.
  Its certificate fingerprint is pinned from the announce; the TLS verifier then rejects
  any other certificate on every path. Each later scan refreshes its LAN, public and relay
  addresses.
- **Trust:** an announce is unauthenticated, so the first contact trusts whatever answers
  on the local network (like Bluetooth pairing). The PIN is still required, and after the
  first contact the pinned fingerprint protects every later connection, including those
  from other networks.

**Internet reachability (UPnP, `reach::keep_port_mapped`):**

- **Router search:** SSDP from every private IPv4 adapter at once. The default route is
  often a VPN while the router is on Ethernet or Wi-Fi.
- **Mapping:** TCP `port → this adapter:port`, with a 1 h lease renewed every 30 min. If
  the router refuses the same external port (another computer has it), any free port is used.
- **Announced:** `public` = the router's WAN address and the mapped port.
- **Notes for the app (`public_note`):**
  - no UPnP router found;
  - carrier-grade NAT (the WAN address is private or `100.64/10`): no `public`;
  - a VPN carries the default route, so replies to forwarded connections would leave
    through it.
- **Shutdown:** the mapping is removed when the service stops.
- **Connecting** (`conn::connect_computer`): races TCP to the LAN address, then 300 ms later
  the public one, takes the first that connects, and runs TLS with the pinned fingerprint.
  If neither connects it goes through the relay, if the computer has one.

**Lockouts with short PINs:**

- 5 failures in a row lock the account (5 min, doubling to 1 h).
- 10 in a row switch the PIN off until it is set again on the host.
- Device tokens skip both checks and never count as failures, so guessing PINs can't lock
  the owner's devices out.

## Who is connected (host notice)

- The daemon keeps a label per viewer (`user on device`, from `ClientHello.device`) and sends the
  list to the agent (`AgentCmd::Viewers`) whenever it changes.
- The agent (`rd-host/src/notice.rs`) starts `rd-client notice --connect 127.0.0.1:PORT` from next to
  its own binary while the list is non-empty. From the Windows service the agent runs as SYSTEM, so
  the window is started as the signed-in console user (`WTSQueryUserToken` + `CreateProcessAsUserW`,
  with that user's environment block).
- The window proves itself with a one-time token (`RD_NOTICE_TOKEN`), then gets
  `viewers\t...` lines and answers `disconnect`, which becomes `AgentEvent::EndSessions`: the daemon
  closes the desk and every viewer gets *The person at NAME ended the session.*
- It closes when the agent's connection drops. Without `rd-client` installed, Linux uses `notify-send`.

## Dynamic DNS, Wake-on-LAN, app install

- **Dynamic DNS** (`reach::keep_port_mapped`): settings `ddns_host` + `ddns_url` (`{ip}` placeholder).
  The router is asked every 5 minutes; when its address changes (or once a day) the URL is fetched
  with `rd_core::http::get`, a minimal HTTPS/1.1 client with the webpki root store. The announce then
  carries `public_name = name:port`, which the app saves and tries after the LAN and public addresses.
- **Wake-on-LAN:** the announce carries up to three universally administered MAC addresses (Linux:
  `/sys/class/net/*` with a `device` link, wired first; Windows: `getmac`). *Wake up* sends the magic
  packet (6×`FF` + 16×MAC) to every local broadcast address and the computer's /24, UDP 9 and 7.
- **App install:** `rd-host install` copies `rd-client` from next to itself to the install folder,
  adds a Start menu shortcut (`WScript.Shell`) or `/usr/share/applications/rd-remote-desktop.desktop`
  (left alone if a package owns it), and turns on Wake-on-LAN on request.

## Several viewers on one desktop

All viewers share one agent through a **desk**:

- **Tile canvas:** the daemon keeps the latest LZ4-compressed version of every 64×64 tile, each with a version number.
- **Per-viewer watermark:** each viewer remembers the newest version it has been sent. On every change it gets only the newer tiles.
  - A slow viewer skips intermediate states instead of building up a backlog or slowing anyone else.
  - A new viewer starts from a full keyframe straight from the canvas, with no need to ask the agent.
- **Audio:** each viewer has a bounded queue, and chunks are dropped for viewers that fall behind.
- **File replies:** routed to the viewer that asked, by request id.
- **Lifetime:** the agent is stopped when the last viewer leaves.
- **Permissions:** enforced per viewer in the daemon. Input from a view-only account is dropped before it ever reaches the agent.

## Protocol (v6)

Messages are postcard-encoded with a `u32` length prefix.

**Client to host, inside TLS:**

1. `ClientHello { username, credential: Password | Pin | DeviceToken, remember_device_as, mode }`
2. `LoginResult::Ok { user, device_token? } | Denied`
3. Then, depending on the mode:
   - `Mode::Desktop`:
     - host → client `HostMsg::{Frame, Video, Codec, Status, Displays, Clipboard, Audio, Files, Viewers, Bye}`
     - client → host `ClientMsg::{Input, RequestKeyframe, SelectDisplay, Clipboard, SecureAttention, SetAudio, Files, SetCodec, Disconnect}`
   - `Mode::Admin`: request/response `AdminRequest` / `AdminResponse`.

**Other details:**

- **File downloads** are flow-controlled: at most 8 × 128 KiB chunks in flight, each acknowledged by the viewer.
- **Uploads** go through a bounded client-side queue.
- **Clipboard** messages carry one of:
  - `ClipData::Text`, at most 1 MiB;
  - `ClipData::Image { width, height, png }`, at most 7680×4320 pixels and 32 MiB of PNG;
  - `ClipData::Files(Vec<ClipFile { path, is_dir, data }>)`, at most 256 entries and 32 MiB in total.
- **Clipboard worker:** host and client share one worker (`rd_core::clipboard`) that polls on its own thread, skips work when Windows' clipboard sequence number hasn't changed, and remembers what it set so nothing echoes back.
- **Copied files:**
  - **Reading:** read from the OS file list (CF_HDROP, `text/uri-list`), recursing into folders without following links.
  - **Receiving:** the receiver checks every path (relative, plain names only, no Windows device names), writes the set under `<temp>/rd-clipboard/<stamp>/` (replacing the previous set) and puts the top-level paths on its clipboard.
  - **Permissions:** the daemon requires both the clipboard and files permissions, in both directions.
- **X11 clipboard lifetime:** contents live in the owning process. On shutdown the worker joins its thread, so arboard can hand them to the desktop's clipboard manager before the agent exits.
- **Keys** are sent as Linux evdev codes. X11 adds 8; the portal uses them directly; Windows maps them to set-1 scan codes.

**Relay (`rd-core::relay`):**

1. The host keeps a control connection: `Host { id, secret, key }`.
2. A client sends `Client { id }`.
3. The relay sends the host `Connect { session }`.
4. The host opens a data connection: `Accept { id, secret, session }`.
5. The relay splices the client and data connections together.

**Peer-to-peer (relay protocol v3, `rd-core::p2p`):**

1. **Discovery:**
   - Before step 2, the client binds a fresh UDP socket. It is dual-stack (IPv6 that also carries IPv4) where the OS allows.
   - The client probes the relay's UDP port over each address family the relay has. The relay answers with the address it saw.
   - Replies are never larger than requests and are rate-limited per IP.
   - The relay binds an extra IPv6-only UDP socket when it listens on `0.0.0.0`.
2. **Exchange:**
   - The client sends `Client { id, candidates, token }`. The candidates are its public addresses plus its LAN IPv4 and global IPv6 addresses; link-local ones are dropped.
   - The host does the same probe when `Connect` arrives and sends its own candidates in `Accept`.
   - The client receives them in `RelayReply::Peer { candidates, udp_relay }`.
   - The relay sets up a UDP allocation for the token, when allowed, and says so to both sides (`udp_relay`).
3. **Punching:** both sides send small UDP packets to each other's candidates every 100 ms, from a clone of the socket the QUIC endpoint uses, so each NAT opens a mapping toward the other side.
4. **Connection:**
   - The host runs a QUIC server on its socket for 8 s.
   - The client races QUIC connections to every host candidate for 3 s, then opens one stream starting with `RDS1` and the token.
   - **Relayed QUIC:** with `udp_relay`, the client also tries the relay's UDP address, 0.5 s later so a direct path wins when there is one.
     - **Header:** a wrapper around the endpoint's socket (`RelayedSocket`) prefixes datagrams to that address with a 21-byte header: `RDU1`, the 16-byte allocation id from the token, and the role (client or host). It strips the header from datagrams coming back.
     - **Forwarding:** the relay learns each side's address from its packets and forwards datagrams unchanged to the other side.
     - **Expiry:** allocations expire after 60 s of silence. `--no-udp-relay` turns forwarding off.
   - The host accepts only the stream with the right token.
5. **Session:** the normal TLS handshake (pinned certificate), sign-in and session protocol run inside that stream. QUIC's own TLS uses a throwaway certificate, because the inner TLS session is what authenticates the host.
6. **Fallback:** if no QUIC connection (direct or relayed) is made in time, the client uses the relayed TCP stream it already holds. If one is made, it drops the TCP stream unused.

**Measured over loopback through the relay:**

| Path | H.264 video | Other traffic | Relay's TCP side |
|---|---|---|---|
| Peer-to-peer | yes | – | nothing |
| Relayed UDP | 30 fps | a 20 MB upload, byte-identical | nothing |
| TCP relay | lossless tiles, 30 fps | – | carried the session |

## Media

- **Capture → daemon:** the agent always sends dirty 64×64 tiles, lossless, LZ4-compressed BGR, into the desk's canvas. The capture thread uses a bounded queue, so a slow link lowers the frame rate rather than adding latency.
- **Daemon → viewer:** each viewer picks a codec with `SetCodec`.
  - **Tiles:** the canvas deltas are sent as they are.
  - **H.264 (default in the app):** the viewer gets its own tile decoder and H.264 encoder (`rd-host/src/video_pipe.rs`).
    - **Hardware first (Windows):** with `--video-encoder auto` (the default), `VideoEncoder` opens the first hardware encoder MFT that accepts the size: NVIDIA, AMD or Intel through Media Foundation.
      - **Stream settings:** NV12 in system memory, limited-range BT.601 like OpenH264, Baseline profile, no B-frames, low-latency mode. Peak-constrained VBR capped at the target bitrate, since CBR pads a still screen up to the full rate.
      - **Sequence headers:** SPS/PPS are prepended to keyframes when the encoder doesn't repeat them, so any client's OpenH264 decoder can join.
      - **Fallback:** the first error switches that viewer to OpenH264 for good, starting with a fresh keyframe.
      - **Measured at 1080p on the AMD encoder:** about 3 ms of CPU per frame (the NV12 conversion), against 12 ms for OpenH264.
      - **NVIDIA on Optimus laptops:** the NVIDIA MFT refused to activate on this laptop, where that GPU doesn't drive a display, so the next encoder was used.
    - **Pacing:** its send loop pulls the newest canvas state whenever the link is ready, so each frame is a valid P-frame against what that viewer last received, and a slow link just gets fewer frames.
    - **Bitrate:** a write that takes over two frame intervals cuts the bitrate by 30%; three calm seconds raise it by 15%, up to `--video-kbps`.
    - **OpenH264 mode:** real-time camera mode. Without OpenH264's assembly, screen-content mode took 48 ms per 1080p frame against 10 ms.
    - **Limits:** pictures larger than 3840×2160 fall back to tiles.
  - **Sharpening:** every 250 ms the daemon resends, as exact lossless tiles, any cell that H.264 drew and that has been still for 300 ms. It uses the whole tick's share of the link when nothing moves, and a quarter of it while video is flowing. Each cell remembers which canvas version it last got losslessly, so a moving area elsewhere (a video, a spinner) doesn't stall the rest.
  - **Client merge:** the client copies only the 16×16 blocks whose decoded H.264 output changed into its framebuffer, so sharpened areas stay sharp until they really change.
  - **Measured on a 1080p desktop with a moving window:** both modes ran at about 22 fps. Lossless used 12.9 Mbit/s, H.264 3.2 Mbit/s (default cap) or 0.7 Mbit/s (1.5 Mbit/s cap). After 8 s still, 99% of the still pixels were identical to lossless.
- **Audio:** 48 kHz stereo, IMA ADPCM (4:1, about 384 kbit/s), in 20 ms chunks. Each chunk carries its own predictor state, so losing one never corrupts the next.
  - **Host capture:** WASAPI loopback (Windows) or `parec` on the default monitor source (Linux).
  - **Client playback:** cpal, with linear resampling and a 200 ms cap on buffering.

## Capture backends

| Backend | Capture | Displays | Input |
|---|---|---|---|
| Windows | DXGI Desktop Duplication on the selected monitor's adapter, with a GDI seed and fallback | `EnumDisplayMonitors` | `SendInput` (scan codes) |
| X11 | `XShmGetImage` of the monitor's rectangle (falls back to `GetImage`) | RandR monitors | XTest |
| Wayland | Portal ScreenCast → PipeWire, reconnecting to another stream node when switching | Streams the user picked in the portal dialog | Portal RemoteDesktop `Notify*` |

## Notes and limits

- **H.264 licensing:** OpenH264 is compiled from source here. Cisco's patent licence covers only its own prebuilt binaries, so check what applies before distributing builds. The Windows hardware encoders are licensed through the OS and GPU driver.
- **Linux hardware encoding:** not implemented (VA-API/NVENC); Linux hosts use OpenH264. Building with `nasm` installed enables OpenH264's assembly, which is faster.
- **Peer-to-peer** has been tested on one machine (loopback), not across real NATs.
- **Host notice:** tested with a Linux host in WSL on Xvfb and the Windows client: the window
  appears with the viewer's name, and its Disconnect button ends the sessions. Not yet tried from
  the Windows service (the `CreateProcessAsUserW` path), on a real KDE/GNOME desktop, or with
  dynamic DNS against a real provider and router.
- **Discovery and setup from the app** were tested between Windows and a Linux host in WSL:
  - **Windows ↔ Linux:** discovery across the WSL virtual network, PIN sign-in, wrong-PIN
    handling, *don't ask again*, offline and reinstalled computers.
  - **Linux setup path:** set up and turn off through `pkexec` and systemd.
  - **Not yet run:** the Windows setup path (a UAC prompt) and a real router port mapping
    reached from outside. `rd-host router-check` found this network's router and its
    address, changing nothing.
- **Linux** builds and passes its tests on Ubuntu 24.04. The X11 host, the client and the systemd install were run there (under Xvfb, in WSL). The Wayland portal and PipeWire capture have not yet run against a real desktop session.
