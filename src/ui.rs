//! egui front end: tunnel table in the style of MobaSSHTunnel + identity/key manager.
use crate::run::{Runner, State};
use crate::store::{self, Db, Identity, Kind, Tunnel};
use eframe::egui::{self, Align2, Color32, ComboBox, Grid, RichText, TextEdit};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static ICONS: AtomicBool = AtomicBool::new(false);

/// Registers the Windows icon font (Segoe Fluent Icons / MDL2 Assets) as a fallback for private-use glyphs.
pub fn install_icons(ctx: &egui::Context) {
    let windir = std::path::PathBuf::from(std::env::var_os("WINDIR").unwrap_or_else(|| "C:\\Windows".into()));
    let Some(bytes) = ["segoeicons.ttf", "segmdl2.ttf"].iter().find_map(|f| std::fs::read(windir.join("Fonts").join(f)).ok()) else {
        return;
    };
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert("icons".into(), std::sync::Arc::new(egui::FontData::from_owned(bytes)));
    for fam in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        fonts.families.entry(fam).or_default().push("icons".into());
    }
    ctx.set_fonts(fonts);
    ICONS.store(true, Ordering::Relaxed);
}

/// "<icon> label" when the icon font is available, plain label otherwise.
fn ic(icon: char, label: &str) -> String {
    if ICONS.load(Ordering::Relaxed) { format!("{icon}  {label}") } else { label.to_string() }
}

const GREEN: Color32 = Color32::from_rgb(10, 125, 44);
const RED: Color32 = Color32::from_rgb(200, 60, 45);

struct TunnelDraft {
    id: Option<String>,
    kind: Kind,
    name: String,
    listen: String,
    dest_host: String,
    dest_port: String,
    ssh_host: String,
    ssh_port: String,
    identity: Option<String>,
    autostart: bool,
    err: String,
}

impl TunnelDraft {
    fn new(t: Option<&Tunnel>, default_identity: Option<String>) -> Self {
        match t {
            Some(t) => Self {
                id: Some(t.id.clone()),
                kind: t.kind,
                name: t.name.clone(),
                listen: t.listen_port.to_string(),
                dest_host: t.dest_host.clone(),
                dest_port: if t.kind == Kind::Dynamic { String::new() } else { t.dest_port.to_string() },
                ssh_host: t.ssh_host.clone(),
                ssh_port: t.ssh_port.to_string(),
                identity: Some(t.identity.clone()),
                autostart: t.autostart,
                err: String::new(),
            },
            None => Self {
                id: None,
                kind: Kind::Local,
                name: String::new(),
                listen: String::new(),
                dest_host: String::new(),
                dest_port: String::new(),
                ssh_host: String::new(),
                ssh_port: "22".into(),
                identity: default_identity,
                autostart: false,
                err: String::new(),
            },
        }
    }

    fn build(&self) -> Result<Tunnel, String> {
        let port = |s: &str| s.trim().parse::<u16>().ok().filter(|p| *p > 0).ok_or("Ports must be numbers between 1 and 65535.");
        let dynamic = self.kind == Kind::Dynamic;
        let (name, host, dest) = (self.name.trim(), self.ssh_host.trim(), self.dest_host.trim());
        if name.is_empty() || host.is_empty() || (!dynamic && dest.is_empty()) || self.identity.is_none() {
            return Err("Fill in all fields and pick an identity (use Manage... to create one).".into());
        }
        Ok(Tunnel {
            id: self.id.clone().unwrap_or_else(store::new_id),
            kind: self.kind,
            name: name.into(),
            listen_port: port(&self.listen)?,
            dest_host: if dynamic { String::new() } else { dest.into() },
            dest_port: if dynamic { 0 } else { port(&self.dest_port)? },
            ssh_host: host.into(),
            ssh_port: port(&self.ssh_port)?,
            identity: self.identity.clone().unwrap_or_default(),
            autostart: self.autostart,
        })
    }

    fn hint(&self) -> String {
        let q = |s: &str| if s.trim().is_empty() { "?".to_string() } else { s.trim().to_string() };
        let (l, d) = (q(&self.listen), format!("{}:{}", q(&self.dest_host), q(&self.dest_port)));
        match self.kind {
            Kind::Local => format!("Local clients can access {d} by connecting to localhost:{l}"),
            Kind::Remote => format!("Clients on the SSH server can reach {d} via localhost:{l} on the server"),
            Kind::Dynamic => format!("Set your app's SOCKS5 proxy to localhost:{l}"),
        }
    }
}

#[derive(Default)]
struct IdDraft {
    id: Option<String>,
    name: String,
    user: String,
    key: Option<String>,
    secret: String,
    err: String,
}

#[derive(Default)]
struct KeyDraft {
    name: String,
    rsa: bool,
    pw: String,
    err: String,
}

struct ImportDraft {
    path: std::path::PathBuf,
    name: String,
    err: String,
}

#[derive(Default)]
struct MasterDraft {
    pw: String,
    pw2: String,
    remember: bool,
    /// "forgot password" confirmation is showing
    reset: bool,
    err: String,
}

impl MasterDraft {
    /// Password field(s) + remember checkbox. `confirm` asks for the password twice (create / change). True on Enter.
    fn form(&mut self, ui: &mut egui::Ui, confirm: bool) -> bool {
        let r = ui.add(TextEdit::singleline(&mut self.pw).password(true).hint_text("Master password").desired_width(260.0));
        if ui.memory(|m| m.focused().is_none()) {
            r.request_focus();
        }
        let mut enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if confirm {
            let r = ui.add(TextEdit::singleline(&mut self.pw2).password(true).hint_text("Repeat master password").desired_width(260.0));
            enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        }
        ui.checkbox(&mut self.remember, "Remember on this computer (don't ask at startup)");
        if !self.err.is_empty() {
            ui.colored_label(RED, &self.err);
        }
        enter
    }

    fn check_new(&mut self) -> bool {
        self.err = if self.pw.is_empty() {
            "Master password cannot be empty.".into()
        } else if self.pw != self.pw2 {
            "Passwords do not match.".into()
        } else {
            String::new()
        };
        self.err.is_empty()
    }
}

#[derive(Default)]
enum Dlg {
    #[default]
    None,
    Master(MasterDraft),
    Tunnel(TunnelDraft),
    Identity(IdDraft),
    KeyGen(KeyDraft),
    Import(ImportDraft),
    Delete(String),
}

enum Act {
    Start(String),
    Stop(String),
    Edit(String),
    Delete(String),
}

pub struct App {
    db: Db,
    runner: Runner,
    dlg: Dlg,
    /// dialog opened from the manager window; separate slot so it doesn't replace a tunnel dialog left open
    sub: Dlg,
    mgr_open: bool,
    mgr_keys: bool,
    msg: Option<(bool, String)>,
    last_tick: Instant,
    /// create / unlock screen shown while the db is locked
    gate: MasterDraft,
}

impl App {
    pub fn new() -> Self {
        let mut db = Db::load();
        db.unlock_saved();
        let gate = MasterDraft { remember: db.remembers(), ..Default::default() };
        let mut app = Self { db, runner: Runner::default(), dlg: Dlg::None, sub: Dlg::None, mgr_open: false, mgr_keys: false, msg: None, last_tick: Instant::now(), gate };
        if !app.db.locked() {
            app.autostart();
        }
        app
    }

    fn autostart(&mut self) {
        for t in self.db.tunnels.iter().filter(|t| t.autostart) {
            self.runner.start(&self.db, t, false);
        }
    }

    /// Full-window screen: create the master password on first run, otherwise ask for it.
    fn gate(&mut self, ui: &mut egui::Ui) {
        let create = self.db.vault.is_none();
        let d = &mut self.gate;
        let mut go = false;
        ui.vertical_centered(|ui| {
            ui.add_space(50.0);
            ui.heading(if create { "Create a master password" } else { "Enter master password" });
            ui.weak(if create {
                "It encrypts saved passwords and key passphrases. It cannot be recovered if forgotten."
            } else {
                "Munnel is locked. The master password decrypts saved passwords."
            });
            ui.add_space(10.0);
            if d.reset {
                ui.colored_label(RED, "Reset deletes every saved password and passphrase. Tunnels, identities and keys are kept.");
                ui.horizontal(|ui| {
                    ui.add_space(ui.available_width() / 2.0 - 70.0);
                    if ui.button("Reset").clicked() {
                        self.db.reset_master();
                        *d = MasterDraft::default();
                    }
                    if ui.button("Cancel").clicked() {
                        d.reset = false;
                    }
                });
                return;
            }
            go = d.form(ui, create);
            ui.add_space(6.0);
            go |= ui.button(if create { "Create" } else { "Unlock" }).clicked();
            if !create && ui.link("Forgot master password?").clicked() {
                d.reset = true;
            }
        });
        if !go {
            return;
        }
        let ok = if create {
            d.check_new() && self.db.set_master(&d.pw, d.remember).map_err(|e| d.err = format!("Cannot save: {e}")).is_ok()
        } else if self.db.unlock(&d.pw) {
            // (un)remembering needs the key re-sealed; set_master does that and re-encrypts with a fresh salt
            if d.remember != self.db.remembers() {
                let _ = self.db.set_master(&d.pw, d.remember);
            }
            true
        } else {
            d.err = "Wrong master password.".into();
            false
        };
        if ok {
            self.gate = MasterDraft::default();
            self.autostart();
        }
    }

    fn master_dlg(&mut self, ctx: &egui::Context, d: &mut MasterDraft) -> bool {
        let (mut save, mut keep) = (false, true);
        window("Change master password").show(ctx, |ui| {
            save = d.form(ui, true);
            ui.horizontal(|ui| {
                save |= ui.button("Save").clicked();
                keep = !ui.button("Cancel").clicked();
            });
        });
        if save && d.check_new() {
            match self.db.set_master(&d.pw, d.remember) {
                Ok(()) => {
                    self.msg = Some((false, "Master password changed.".into()));
                    return false;
                }
                Err(e) => d.err = format!("Cannot save: {e}"),
            }
        }
        keep
    }

    fn save(&mut self) {
        if let Err(e) = self.db.save() {
            self.msg = Some((true, format!("Cannot save: {e}")));
        }
    }

    fn table(&mut self, ui: &mut egui::Ui) {
        let (mut act, mut dirty) = (None, false);
        egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
            Grid::new("tunnels").striped(true).spacing([16.0, 8.0]).show(ui, |ui| {
                for h in ["Name", "Type", "Start/stop", "Status", "Forward port", "Destination server", "SSH server", "Settings"] {
                    ui.strong(h);
                }
                ui.end_row();
                for t in &mut self.db.tunnels {
                    let r = ui.add_sized([150.0, 22.0], TextEdit::singleline(&mut t.name));
                    if r.lost_focus() {
                        if t.name.trim().is_empty() {
                            t.name = "tunnel".into();
                        }
                        dirty = true;
                    }
                    ui.strong(t.kind.label());
                    let state = self.runner.state(&t.id);
                    let busy = matches!(state, State::Running | State::Reconnecting(_));
                    ui.horizontal(|ui| {
                        if ui.add_enabled(!busy, egui::Button::new(ic('\u{E768}', "Start"))).clicked() {
                            act = Some(Act::Start(t.id.clone()));
                        }
                        if ui.add_enabled(state != State::Stopped, egui::Button::new(ic('\u{E71A}', "Stop"))).clicked() {
                            act = Some(Act::Stop(t.id.clone()));
                        }
                    });
                    let (txt, color) = match state {
                        State::Stopped => ("stopped".to_string(), Color32::GRAY),
                        State::Running => ("running".to_string(), GREEN),
                        State::Error(e) => (format!("error: {e}"), RED),
                        State::Reconnecting(e) => (format!("reconnecting... ({e})"), RED),
                    };
                    ui.scope(|ui| {
                        ui.set_width(240.0);
                        ui.add(egui::Label::new(RichText::new(&txt).color(color)).truncate()).on_hover_text(&txt);
                    });
                    ui.label(t.listen_port.to_string());
                    ui.label(if t.kind == Kind::Dynamic { "SOCKS5 proxy".into() } else { format!("{}:{}", t.dest_host, t.dest_port) });
                    let user = self.db.identities.iter().find(|i| i.id == t.identity).map_or("?", |i| i.user.as_str());
                    ui.label(format!("{user}@{}:{}", t.ssh_host, t.ssh_port));
                    ui.horizontal(|ui| {
                        if ui.button(ic('\u{E70F}', "Edit")).clicked() {
                            act = Some(Act::Edit(t.id.clone()));
                        }
                        if ui.button(ic('\u{E74D}', "Delete")).clicked() {
                            act = Some(Act::Delete(t.id.clone()));
                        }
                    });
                    ui.end_row();
                }
            });
            if self.db.tunnels.is_empty() {
                ui.add_space(30.0);
                ui.vertical_centered(|ui| ui.weak("No tunnels yet - click 'New SSH tunnel'."));
            }
        });
        if dirty {
            self.save();
        }
        match act {
            Some(Act::Start(id)) => self.start(&id),
            Some(Act::Stop(id)) => self.runner.stop(&id),
            Some(Act::Edit(id)) => {
                let t = self.db.tunnels.iter().find(|t| t.id == id);
                self.dlg = Dlg::Tunnel(TunnelDraft::new(t, None));
            }
            Some(Act::Delete(id)) => self.dlg = Dlg::Delete(id),
            None => {}
        }
    }

    fn start(&mut self, id: &str) {
        if let Some(t) = self.db.tunnels.iter().find(|t| t.id == id) {
            self.runner.start(&self.db, t, false);
        }
    }

    fn bar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        if let Some((err, m)) = self.msg.clone() {
            ui.horizontal(|ui| {
                ui.colored_label(if err { RED } else { GREEN }, m);
                if ui.small_button("x").clicked() {
                    self.msg = None;
                }
            });
        }
        ui.horizontal(|ui| {
            if ui.button(ic('\u{E710}', "New SSH tunnel")).clicked() {
                self.dlg = Dlg::Tunnel(TunnelDraft::new(None, self.db.identities.first().map(|i| i.id.clone())));
            }
            if ui.button(ic('\u{E768}', "Start all tunnels")).clicked() {
                let ids: Vec<_> = self.db.tunnels.iter().map(|t| t.id.clone()).collect();
                ids.iter().for_each(|id| self.start(id));
            }
            if ui.button(ic('\u{E71A}', "Stop all tunnels")).clicked() {
                self.runner.stop_all();
            }
            if ui.button(ic('\u{E192}', "Identities & keys")).clicked() {
                self.mgr_open = true;
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button(ic('\u{E7E8}', "Exit")).clicked() {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
                if ui.button(ic('\u{E72E}', "Master password")).clicked() {
                    self.dlg = Dlg::Master(MasterDraft { remember: self.db.remembers(), ..Default::default() });
                }
            });
        });
        ui.add_space(6.0);
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        let d = std::mem::take(&mut self.dlg);
        self.dlg = self.show_dlg(ctx, d);
        if self.mgr_open {
            self.manager(ctx);
        }
        let d = std::mem::take(&mut self.sub);
        self.sub = self.show_dlg(ctx, d);
    }

    fn show_dlg(&mut self, ctx: &egui::Context, dlg: Dlg) -> Dlg {
        match dlg {
            Dlg::Master(mut d) => if self.master_dlg(ctx, &mut d) { Dlg::Master(d) } else { Dlg::None },
            Dlg::Tunnel(mut d) => if self.tunnel_dlg(ctx, &mut d) { Dlg::Tunnel(d) } else { Dlg::None },
            Dlg::Identity(mut d) => if self.identity_dlg(ctx, &mut d) { Dlg::Identity(d) } else { Dlg::None },
            Dlg::KeyGen(mut d) => if self.keygen_dlg(ctx, &mut d) { Dlg::KeyGen(d) } else { Dlg::None },
            Dlg::Import(mut d) => if self.import_dlg(ctx, &mut d) { Dlg::Import(d) } else { Dlg::None },
            Dlg::Delete(id) => if self.delete_dlg(ctx, &id) { Dlg::Delete(id) } else { Dlg::None },
            Dlg::None => Dlg::None,
        }
    }

    fn delete_dlg(&mut self, ctx: &egui::Context, id: &str) -> bool {
        let Some(name) = self.db.tunnels.iter().find(|t| t.id == id).map(|t| t.name.clone()) else { return false };
        let mut keep = true;
        window("Delete tunnel").show(ctx, |ui| {
            ui.label(format!("Delete tunnel '{name}'?"));
            ui.horizontal(|ui| {
                if ui.button("Delete").clicked() {
                    self.runner.stop(id);
                    self.db.tunnels.retain(|t| t.id != id);
                    self.save();
                    keep = false;
                }
                keep &= !ui.button("Cancel").clicked();
            });
        });
        keep
    }

    fn tunnel_dlg(&mut self, ctx: &egui::Context, d: &mut TunnelDraft) -> bool {
        let (mut save, mut keep) = (false, true);
        window("SSH tunnel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.radio_value(&mut d.kind, Kind::Local, "Local port forwarding");
                ui.radio_value(&mut d.kind, Kind::Remote, "Remote port forwarding");
                ui.radio_value(&mut d.kind, Kind::Dynamic, "Dynamic port forwarding (SOCKS proxy)");
            });
            ui.add_space(6.0);
            let (l1, l2, l3) = match d.kind {
                Kind::Local => ("Local listen port", "Remote server host", "Remote server port"),
                Kind::Remote => ("Port on SSH server", "Local destination host", "Local destination port"),
                Kind::Dynamic => ("Local SOCKS port", "", ""),
            };
            let dynamic = d.kind == Kind::Dynamic;
            Grid::new("tf").num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                ui.label("Name");
                ui.add(TextEdit::singleline(&mut d.name).desired_width(260.0));
                ui.end_row();
                ui.label(l1);
                ui.add(TextEdit::singleline(&mut d.listen).desired_width(260.0));
                ui.end_row();
                ui.add_visible(!dynamic, egui::Label::new(l2));
                ui.add_enabled(!dynamic, TextEdit::singleline(&mut d.dest_host).desired_width(260.0));
                ui.end_row();
                ui.add_visible(!dynamic, egui::Label::new(l3));
                ui.add_enabled(!dynamic, TextEdit::singleline(&mut d.dest_port).desired_width(260.0));
                ui.end_row();
                ui.label("SSH server host");
                ui.add(TextEdit::singleline(&mut d.ssh_host).desired_width(260.0));
                ui.end_row();
                ui.label("SSH server port");
                ui.add(TextEdit::singleline(&mut d.ssh_port).desired_width(260.0));
                ui.end_row();
                ui.label("Identity");
                ui.horizontal(|ui| {
                    let cur = d.identity.as_deref().and_then(|id| self.db.identity(id)).map_or("(select)".into(), |i| format!("{} ({})", i.name, i.user));
                    ComboBox::from_id_salt("ident").selected_text(cur).width(190.0).show_ui(ui, |ui| {
                        for i in &self.db.identities {
                            ui.selectable_value(&mut d.identity, Some(i.id.clone()), format!("{} ({})", i.name, i.user));
                        }
                    });
                    if ui.button("Manage...").clicked() {
                        self.mgr_open = true;
                    }
                });
                ui.end_row();
            });
            ui.checkbox(&mut d.autostart, "Start when Munnel opens");
            ui.add_space(4.0);
            ui.label(RichText::new(d.hint()).color(Color32::from_rgb(60, 110, 200)));
            if !d.err.is_empty() {
                ui.colored_label(RED, &d.err);
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                save = ui.button("Save").clicked();
                keep = !ui.button("Cancel").clicked();
            });
        });
        if save {
            match d.build() {
                Ok(t) => {
                    let was_up = matches!(self.runner.state(&t.id), State::Running | State::Reconnecting(_));
                    self.runner.stop(&t.id);
                    match self.db.tunnels.iter_mut().find(|x| x.id == t.id) {
                        Some(old) => *old = t.clone(),
                        None => self.db.tunnels.push(t.clone()),
                    }
                    if was_up {
                        self.runner.start(&self.db, &t, false); // a running tunnel restarts to pick up changes
                    }
                    self.save();
                    return false;
                }
                Err(e) => d.err = e,
            }
        }
        keep
    }

    fn identity_dlg(&mut self, ctx: &egui::Context, d: &mut IdDraft) -> bool {
        let (mut save, mut keep) = (false, true);
        window("Identity").show(ctx, |ui| {
            Grid::new("idf").num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                ui.label("Name");
                ui.add(TextEdit::singleline(&mut d.name).desired_width(240.0));
                ui.end_row();
                ui.label("Username");
                ui.add(TextEdit::singleline(&mut d.user).desired_width(240.0));
                ui.end_row();
                ui.label("Private key");
                let cur = d.key.as_deref().and_then(|k| self.db.key(k)).map_or("(none - password / agent)".into(), |k| k.name.clone());
                ComboBox::from_id_salt("idkey").selected_text(cur).width(240.0).show_ui(ui, |ui| {
                    ui.selectable_value(&mut d.key, None, "(none - password / agent)");
                    for k in &self.db.keys {
                        ui.selectable_value(&mut d.key, Some(k.id.clone()), &k.name);
                    }
                });
                ui.end_row();
                ui.label("Password / key passphrase");
                ui.add(TextEdit::singleline(&mut d.secret).password(true).desired_width(240.0));
                ui.end_row();
            });
            ui.weak("Encrypted with your master password. Leave empty for passwordless keys.");
            if !d.err.is_empty() {
                ui.colored_label(RED, &d.err);
            }
            ui.horizontal(|ui| {
                save = ui.button("Save").clicked();
                keep = !ui.button("Cancel").clicked();
            });
        });
        if save {
            if d.name.trim().is_empty() || d.user.trim().is_empty() {
                d.err = "Name and username are required.".into();
            } else {
                let i = Identity {
                    id: d.id.clone().unwrap_or_else(store::new_id),
                    name: d.name.trim().into(),
                    user: d.user.trim().into(),
                    key: d.key.clone(),
                    secret: d.secret.clone(),
                };
                match self.db.identities.iter_mut().find(|x| x.id == i.id) {
                    Some(old) => *old = i,
                    None => self.db.identities.push(i),
                }
                self.save();
                return false;
            }
        }
        keep
    }

    fn keygen_dlg(&mut self, ctx: &egui::Context, d: &mut KeyDraft) -> bool {
        let (mut save, mut keep) = (false, true);
        window("Generate SSH key").show(ctx, |ui| {
            Grid::new("kg").num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                ui.label("Key name");
                ui.add(TextEdit::singleline(&mut d.name).desired_width(220.0));
                ui.end_row();
                ui.label("Type");
                ui.horizontal(|ui| {
                    ui.radio_value(&mut d.rsa, false, "ed25519");
                    ui.radio_value(&mut d.rsa, true, "rsa 4096");
                });
                ui.end_row();
                ui.label("Passphrase (optional)");
                ui.add(TextEdit::singleline(&mut d.pw).password(true).desired_width(220.0));
                ui.end_row();
            });
            if !d.err.is_empty() {
                ui.colored_label(RED, &d.err);
            }
            ui.horizontal(|ui| {
                save = ui.button("Generate").clicked();
                keep = !ui.button("Cancel").clicked();
            });
        });
        if save {
            if d.name.trim().is_empty() {
                d.err = "Key name is required.".into();
            } else {
                match store::generate_key(&mut self.db, d.name.trim(), if d.rsa { "rsa" } else { "ed25519" }, &d.pw) {
                    Ok(()) => {
                        self.save();
                        return false;
                    }
                    Err(e) => d.err = e,
                }
            }
        }
        keep
    }

    fn import_dlg(&mut self, ctx: &egui::Context, d: &mut ImportDraft) -> bool {
        let (mut save, mut keep) = (false, true);
        window("Import SSH key").show(ctx, |ui| {
            ui.weak(d.path.display().to_string());
            ui.horizontal(|ui| {
                ui.label("Key name");
                ui.add(TextEdit::singleline(&mut d.name).desired_width(220.0));
            });
            if !d.err.is_empty() {
                ui.colored_label(RED, &d.err);
            }
            ui.horizontal(|ui| {
                save = ui.button("Import").clicked();
                keep = !ui.button("Cancel").clicked();
            });
        });
        if save {
            if d.name.trim().is_empty() {
                d.err = "Key name is required.".into();
            } else {
                match store::import_key(&mut self.db, &d.path, d.name.trim()) {
                    Ok(()) => {
                        self.save();
                        return false;
                    }
                    Err(e) => d.err = e,
                }
            }
        }
        keep
    }

    fn manager(&mut self, ctx: &egui::Context) {
        let mut open = true;
        egui::Window::new("Identities & SSH keys").open(&mut open).default_width(560.0).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.mgr_keys, false, "Identities");
                ui.selectable_value(&mut self.mgr_keys, true, "SSH keys");
            });
            ui.separator();
            if self.mgr_keys { self.keys_tab(ui, ctx) } else { self.identities_tab(ui) }
        });
        self.mgr_open = open;
    }

    fn identities_tab(&mut self, ui: &mut egui::Ui) {
        let (mut edit, mut del) = (None, None);
        Grid::new("ids").striped(true).spacing([16.0, 6.0]).show(ui, |ui| {
            for h in ["Name", "User", "Key", "Auth", ""] {
                ui.strong(h);
            }
            ui.end_row();
            for i in &self.db.identities {
                ui.label(&i.name);
                ui.label(&i.user);
                ui.label(i.key.as_deref().and_then(|k| self.db.key(k)).map_or("", |k| k.name.as_str()));
                ui.label(if i.secret.is_empty() { "key / agent" } else { "password/passphrase" });
                ui.horizontal(|ui| {
                    edit = ui.button("Edit").clicked().then(|| i.clone()).or(edit.take());
                    del = ui.button("Delete").clicked().then(|| i.id.clone()).or(del.take());
                });
                ui.end_row();
            }
        });
        if ui.button(ic('\u{E710}', "New identity")).clicked() {
            self.sub = Dlg::Identity(IdDraft::default());
        }
        if let Some(i) = edit {
            self.sub = Dlg::Identity(IdDraft { id: Some(i.id), name: i.name, user: i.user, key: i.key, secret: i.secret, err: String::new() });
        }
        if let Some(id) = del {
            if self.db.tunnels.iter().any(|t| t.identity == id) {
                self.msg = Some((true, "Identity is used by a tunnel.".into()));
            } else {
                self.db.identities.retain(|i| i.id != id);
                self.save();
            }
        }
    }

    fn keys_tab(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let (mut copy, mut del) = (None, None);
        Grid::new("keys").striped(true).spacing([16.0, 6.0]).show(ui, |ui| {
            for h in ["Name", "File", ""] {
                ui.strong(h);
            }
            ui.end_row();
            for k in &self.db.keys {
                ui.label(&k.name);
                ui.label(&k.file);
                ui.horizontal(|ui| {
                    copy = ui.button(ic('\u{E8C8}', "Copy public key")).clicked().then(|| k.clone()).or(copy.take());
                    del = ui.button("Delete").clicked().then(|| k.clone()).or(del.take());
                });
                ui.end_row();
            }
        });
        ui.horizontal(|ui| {
            if ui.button(ic('\u{E710}', "Generate...")).clicked() {
                self.sub = Dlg::KeyGen(KeyDraft::default());
            }
            if ui.button(ic('\u{E896}', "Import...")).clicked() {
                let start = std::env::var_os("USERPROFILE").map(|p| std::path::PathBuf::from(p).join(".ssh"));
                let mut fd = rfd::FileDialog::new().set_title("Select private key");
                if let Some(s) = start.filter(|s| s.exists()) {
                    fd = fd.set_directory(s);
                }
                if let Some(path) = fd.pick_file() {
                    let name = path.file_stem().map_or("key".into(), |s| s.to_string_lossy().into_owned());
                    self.sub = Dlg::Import(ImportDraft { path, name, err: String::new() });
                }
            }
        });
        if let Some(k) = copy {
            match store::pubkey(&store::keys_dir().join(&k.file)) {
                Some(p) => {
                    ctx.copy_text(p);
                    self.msg = Some((false, "Public key copied. Append it to ~/.ssh/authorized_keys on the server.".into()));
                }
                None => self.msg = Some((true, "Cannot read the public key (passphrase protected and no .pub file).".into())),
            }
        }
        if let Some(k) = del {
            if self.db.identities.iter().any(|i| i.key.as_deref() == Some(&k.id)) {
                self.msg = Some((true, "Key is used by an identity.".into()));
            } else {
                let _ = std::fs::remove_file(store::keys_dir().join(&k.file));
                let _ = std::fs::remove_file(store::keys_dir().join(format!("{}.pub", k.file)));
                self.db.keys.retain(|x| x.id != k.id);
                self.msg = None;
                self.save();
            }
        }
    }
}

fn window(title: &str) -> egui::Window<'_> {
    egui::Window::new(title).collapsible(false).resizable(false).anchor(Align2::CENTER_CENTER, [0.0, 0.0])
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        ui.style_mut().interaction.selectable_labels = false;
        let ctx = ui.ctx().clone();
        if self.db.locked() {
            egui::CentralPanel::default().show(ui, |ui| self.gate(ui));
            return;
        }
        if self.last_tick.elapsed() >= Duration::from_secs(1) {
            self.runner.tick(&self.db);
            self.last_tick = Instant::now();
        }
        ctx.request_repaint_after(Duration::from_millis(500));
        egui::Panel::bottom("bar").show(ui, |ui| self.bar(ui));
        egui::CentralPanel::default().show(ui, |ui| self.table(ui));
        self.dialogs(&ctx);
    }

    fn on_exit(&mut self) {
        self.runner.stop_all();
    }
}
