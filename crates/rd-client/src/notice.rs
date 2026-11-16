//! `rd-client notice`: the small always-on-top window on the *host's* screen while
//! someone is connected ("Your screen is being shared with ..." + Disconnect).
//!
//! Started by the host's desktop agent, which it connects back to over loopback with
//! the one-time token in `RD_NOTICE_TOKEN` (see `rd-host/src/notice.rs`). It closes by
//! itself when the agent goes away.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use egui::{Color32, RichText};

#[derive(Default)]
struct Shared {
    viewers: Vec<String>,
    ctx: Option<egui::Context>,
}

pub struct Notice {
    shared: Arc<Mutex<Shared>>,
    writer: TcpStream,
    disconnecting: bool,
}

impl Notice {
    /// Connect to the agent at `addr` and start listening for viewer updates.
    pub fn connect(addr: &str) -> Result<Notice> {
        let token = std::env::var("RD_NOTICE_TOKEN").context("RD_NOTICE_TOKEN not set (this window is opened by the host)")?;
        std::env::remove_var("RD_NOTICE_TOKEN");
        let mut s = TcpStream::connect(addr).with_context(|| format!("connect to {addr}"))?;
        s.write_all(format!("{token}\n").as_bytes())?;
        let shared: Arc<Mutex<Shared>> = Arc::default();
        let (reader, sh) = (s.try_clone()?, shared.clone());
        std::thread::spawn(move || {
            for line in BufReader::new(reader).lines() {
                let Ok(line) = line else { break };
                if let Some(rest) = line.strip_prefix("viewers") {
                    let list: Vec<String> = rest.split('\t').filter(|v| !v.is_empty()).map(str::to_string).collect();
                    let mut g = sh.lock().unwrap();
                    g.viewers = list;
                    if let Some(c) = &g.ctx {
                        c.request_repaint();
                    }
                }
            }
            // The agent is gone: the session is over.
            std::process::exit(0);
        });
        Ok(Notice { shared, writer: s, disconnecting: false })
    }

    pub fn ui(&mut self, ctx: &egui::Context) {
        let viewers = {
            let mut g = self.shared.lock().unwrap();
            if g.ctx.is_none() {
                g.ctx = Some(ctx.clone());
            }
            g.viewers.clone()
        };
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 6.0, Color32::from_rgb(230, 120, 60));
                ui.label(RichText::new("Your screen is being shared").strong().size(15.0));
            });
            ui.add_space(4.0);
            if viewers.is_empty() {
                ui.label("Waiting for the connection...");
            }
            for v in &viewers {
                ui.label(format!("Connected: {v}"));
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if self.disconnecting {
                    ui.spinner();
                    ui.label("Disconnecting...");
                } else {
                    let b = egui::Button::new(RichText::new("Disconnect").color(Color32::WHITE)).fill(Color32::from_rgb(190, 60, 50));
                    if ui.add(b).on_hover_text("End the remote session now").clicked() {
                        let _ = self.writer.write_all(b"disconnect\n");
                        self.disconnecting = true;
                    }
                }
            });
        });
    }

    pub fn title(&self) -> String {
        "RD Remote Desktop - screen shared".into()
    }
}
