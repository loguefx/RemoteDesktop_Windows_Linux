//! `rd-client notice`: the small always-on-top window on the *host's* screen while
//! someone is connected or asking to connect: "Your screen is being shared with ...",
//! Allow / Don't allow for connection requests, chat with the viewers, and Disconnect.
//!
//! Started by the host's desktop agent, which it connects back to over loopback with
//! the one-time token in `RD_NOTICE_TOKEN` (see `rd-host/src/notice.rs` for the line
//! protocol). It closes by itself when the agent goes away.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use egui::{Color32, RichText};

#[derive(Default)]
struct Shared {
    viewers: Vec<String>,
    /// Connection requests waiting for an answer: (id, who).
    asks: Vec<(u32, String)>,
    chat: Vec<(String, String)>,
    ctx: Option<egui::Context>,
}

pub struct Notice {
    shared: Arc<Mutex<Shared>>,
    writer: TcpStream,
    disconnecting: bool,
    chat_input: String,
}

impl Notice {
    /// Connect to the agent at `addr` and start listening for updates.
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
                let mut f = line.split('\t');
                let mut g = sh.lock().unwrap();
                match f.next() {
                    Some("viewers") => g.viewers = f.filter(|v| !v.is_empty()).map(str::to_string).collect(),
                    Some("ask") => {
                        if let (Some(Ok(id)), Some(who)) = (f.next().map(str::parse::<u32>), f.next()) {
                            if !g.asks.iter().any(|(i, _)| *i == id) {
                                g.asks.push((id, who.to_string()));
                            }
                        }
                    }
                    Some("askdone") => {
                        if let Some(Ok(id)) = f.next().map(str::parse::<u32>) {
                            g.asks.retain(|(i, _)| *i != id);
                        }
                    }
                    Some("chat") => {
                        if let (Some(from), Some(text)) = (f.next(), f.next()) {
                            g.chat.push((from.to_string(), text.to_string()));
                        }
                    }
                    _ => {}
                }
                if let Some(c) = &g.ctx {
                    c.request_repaint();
                }
            }
            // The agent is gone: the session is over.
            std::process::exit(0);
        });
        Ok(Notice { shared, writer: s, disconnecting: false, chat_input: String::new() })
    }

    fn send(&mut self, line: &str) {
        let clean = line.replace(['\n', '\r'], " ");
        let _ = self.writer.write_all(format!("{clean}\n").as_bytes());
    }

    pub fn ui(&mut self, ctx: &egui::Context) {
        let (viewers, asks, chat) = {
            let mut g = self.shared.lock().unwrap();
            if g.ctx.is_none() {
                g.ctx = Some(ctx.clone());
            }
            (g.viewers.clone(), g.asks.clone(), g.chat.clone())
        };
        let mut answers: Vec<(u32, bool)> = Vec::new();
        egui::TopBottomPanel::top("state").show(ctx, |ui| {
            ui.add_space(4.0);
            for (id, who) in &asks {
                ui.label(RichText::new(format!("{who} wants to connect to this computer.")).strong());
                ui.horizontal(|ui| {
                    let allow = egui::Button::new(RichText::new("Allow").color(Color32::WHITE)).fill(crate::theme::SUCCESS.gamma_multiply(0.8));
                    if ui.add(allow).clicked() {
                        answers.push((*id, true));
                    }
                    if ui.button("Don't allow").clicked() {
                        answers.push((*id, false));
                    }
                });
                ui.add_space(6.0);
            }
            if !viewers.is_empty() {
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
                    ui.painter().circle_filled(rect.center(), 6.0, crate::theme::WARNING);
                    ui.label(RichText::new("Your screen is being shared").strong().size(15.0));
                });
                for v in &viewers {
                    ui.label(format!("Connected: {v}"));
                }
                ui.horizontal(|ui| {
                    if self.disconnecting {
                        ui.spinner();
                        ui.label("Disconnecting...");
                    } else {
                        let b = egui::Button::new(RichText::new("Disconnect").color(Color32::WHITE)).fill(crate::theme::DANGER);
                        if ui.add(b).on_hover_text("End the remote session now").clicked() {
                            self.send("disconnect");
                            self.disconnecting = true;
                        }
                    }
                });
            } else if asks.is_empty() {
                ui.label("Waiting for the connection...");
            }
            ui.add_space(4.0);
        });
        for (id, allow) in answers {
            self.send(&format!("{}\t{id}", if allow { "allow" } else { "deny" }));
            self.shared.lock().unwrap().asks.retain(|(i, _)| *i != id);
        }
        if viewers.is_empty() {
            egui::CentralPanel::default().show(ctx, |_| {});
            return;
        }
        egui::TopBottomPanel::bottom("say").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let r = ui.add(
                    egui::TextEdit::singleline(&mut self.chat_input).hint_text("Message to the people connected").desired_width(ui.available_width() - 60.0),
                );
                let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if (ui.button("Send").clicked() || enter) && !self.chat_input.trim().is_empty() {
                    let text = std::mem::take(&mut self.chat_input).trim().to_string();
                    self.send(&format!("chat\t{}", text.replace('\t', " ")));
                    self.shared.lock().unwrap().chat.push(("You".into(), text));
                    r.request_focus();
                }
            });
            ui.add_space(4.0);
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
                if chat.is_empty() {
                    ui.label(RichText::new("Chat with the people connected here.").color(Color32::GRAY));
                }
                for (from, text) in &chat {
                    ui.label(RichText::new(from).small().color(Color32::GRAY));
                    ui.label(text);
                }
            });
        });
    }

    pub fn title(&self) -> String {
        let g = self.shared.lock().unwrap();
        if !g.asks.is_empty() {
            "RD Remote Desktop - connection request".into()
        } else {
            "RD Remote Desktop - screen shared".into()
        }
    }
}
