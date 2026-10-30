#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use munnel::ui;

fn main() -> eframe::Result {
    // ssh runs us as SSH_ASKPASS (see run.rs): print the secret and exit.
    if std::env::args().nth(1).as_deref() == Some("--askpass") {
        use std::io::Write;
        let _ = writeln!(std::io::stdout(), "{}", std::env::var("MUNNEL_SECRET").unwrap_or_default());
        return Ok(());
    }
    let viewport = egui::ViewportBuilder::default().with_inner_size([1260.0, 420.0]).with_min_inner_size([820.0, 300.0]);
    eframe::run_native(
        "Munnel - SSH tunnel manager",
        eframe::NativeOptions { viewport, renderer: eframe::Renderer::Wgpu, ..Default::default() },
        Box::new(|cc| {
            ui::install_icons(&cc.egui_ctx);
            Ok(Box::new(ui::App::new()))
        }),
    )
}
