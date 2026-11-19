//! One look for every window the client opens (the app, the installer, the host's
//! "screen is being shared" notice): a dark palette with a blue accent, roomier spacing,
//! rounded controls, and a few helpers (cards, primary and danger buttons, pills).

use egui::{Color32, CornerRadius, FontId, Margin, RichText, Stroke, TextStyle};

pub const ACCENT: Color32 = Color32::from_rgb(59, 130, 246);
pub const ACCENT_HOVER: Color32 = Color32::from_rgb(96, 155, 250);
pub const SUCCESS: Color32 = Color32::from_rgb(74, 190, 120);
pub const WARNING: Color32 = Color32::from_rgb(232, 168, 56);
pub const DANGER: Color32 = Color32::from_rgb(229, 83, 75);
pub const MUTED: Color32 = Color32::from_rgb(140, 147, 160);

pub const BG: Color32 = Color32::from_rgb(19, 21, 26);
pub const SURFACE: Color32 = Color32::from_rgb(28, 31, 38);
pub const SURFACE_HI: Color32 = Color32::from_rgb(36, 40, 49);
pub const BORDER: Color32 = Color32::from_rgb(48, 53, 64);
pub const TEXT: Color32 = Color32::from_rgb(226, 230, 237);

/// Install the theme on `ctx` (once, when the window is created).
pub fn apply(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Dark);
    ctx.style_mut_of(egui::Theme::Dark, |style| {
        style.text_styles = [
            (TextStyle::Heading, FontId::proportional(22.0)),
            (TextStyle::Body, FontId::proportional(14.5)),
            (TextStyle::Button, FontId::proportional(14.5)),
            (TextStyle::Small, FontId::proportional(12.0)),
            (TextStyle::Monospace, FontId::monospace(13.5)),
        ]
        .into();

        let s = &mut style.spacing;
        s.item_spacing = egui::vec2(8.0, 8.0);
        s.button_padding = egui::vec2(12.0, 6.0);
        s.interact_size.y = 30.0;
        s.menu_margin = Margin::same(8);
        s.window_margin = Margin::same(16);
        s.combo_width = 120.0;

        let v = &mut style.visuals;
        v.dark_mode = true;
        v.override_text_color = Some(TEXT);
        v.panel_fill = BG;
        v.window_fill = SURFACE;
        v.window_stroke = Stroke::new(1.0, BORDER);
        v.window_corner_radius = CornerRadius::same(10);
        v.menu_corner_radius = CornerRadius::same(8);
        v.extreme_bg_color = Color32::from_rgb(14, 16, 20);
        v.faint_bg_color = Color32::from_rgb(24, 27, 33);
        v.code_bg_color = SURFACE_HI;
        v.hyperlink_color = ACCENT_HOVER;
        v.warn_fg_color = WARNING;
        v.error_fg_color = DANGER;
        v.selection.bg_fill = ACCENT.gamma_multiply(0.55);
        v.selection.stroke = Stroke::new(1.0, ACCENT_HOVER);

        let radius = CornerRadius::same(6);
        let w = &mut v.widgets;
        w.noninteractive.bg_fill = SURFACE;
        w.noninteractive.weak_bg_fill = SURFACE;
        w.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
        w.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
        w.noninteractive.corner_radius = radius;
        w.inactive.bg_fill = SURFACE_HI;
        w.inactive.weak_bg_fill = SURFACE_HI;
        w.inactive.bg_stroke = Stroke::new(1.0, BORDER);
        w.inactive.fg_stroke = Stroke::new(1.0, TEXT);
        w.inactive.corner_radius = radius;
        w.hovered.bg_fill = Color32::from_rgb(46, 51, 62);
        w.hovered.weak_bg_fill = Color32::from_rgb(46, 51, 62);
        w.hovered.bg_stroke = Stroke::new(1.0, Color32::from_rgb(70, 78, 94));
        w.hovered.fg_stroke = Stroke::new(1.5, Color32::WHITE);
        w.hovered.corner_radius = radius;
        w.hovered.expansion = 0.0;
        w.active.bg_fill = Color32::from_rgb(56, 62, 76);
        w.active.weak_bg_fill = Color32::from_rgb(56, 62, 76);
        w.active.bg_stroke = Stroke::new(1.0, ACCENT);
        w.active.fg_stroke = Stroke::new(1.5, Color32::WHITE);
        w.active.corner_radius = radius;
        w.active.expansion = 0.0;
        w.open.bg_fill = SURFACE_HI;
        w.open.weak_bg_fill = SURFACE_HI;
        w.open.bg_stroke = Stroke::new(1.0, ACCENT);
        w.open.corner_radius = radius;
    });
}

/// A raised, rounded box for grouping a section.
pub fn card() -> egui::Frame {
    egui::Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::same(16))
}

/// A section heading inside a page ("This computer", "My computers").
pub fn section(text: &str) -> RichText {
    RichText::new(text).size(16.0).strong().color(Color32::WHITE)
}

/// Secondary text: hints and explanations.
pub fn hint(text: impl Into<String>) -> RichText {
    RichText::new(text).small().color(MUTED)
}

/// The main action on a screen.
pub fn primary(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.to_owned()).color(Color32::WHITE).strong()).fill(ACCENT)
}

/// An action that ends or removes something.
pub fn danger(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.to_owned()).color(Color32::WHITE)).fill(DANGER.gamma_multiply(0.85))
}

/// A small rounded label with a coloured dot: "Online", "Relay · 40 ms".
pub fn pill(ui: &mut egui::Ui, color: Color32, text: &str) -> egui::Response {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.14))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 4.0, color);
                ui.label(RichText::new(text).small().color(TEXT));
            });
        })
        .response
}

/// A message box tinted by its colour (errors, warnings).
pub fn banner(ui: &mut egui::Ui, color: Color32, text: &str) {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.12))
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.5)))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::symmetric(10, 8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(text).color(color));
        });
}
