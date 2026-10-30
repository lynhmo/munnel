//! Data model + persistence (Documents\Munnel\munnel.json, keys\) + ssh command building.
//! Passwords are encrypted with a key derived from the master password (Argon2id + AES-256-GCM).
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    #[default]
    Local,
    Remote,
    Dynamic,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Local => "Local",
            Kind::Remote => "Remote",
            Kind::Dynamic => "Dynamic",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct Tunnel {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: Kind,
    pub name: String,
    pub listen_port: u16,
    #[serde(default)]
    pub dest_host: String,
    #[serde(default)]
    pub dest_port: u16,
    pub ssh_host: String,
    pub ssh_port: u16,
    pub identity: String,
    #[serde(default)]
    pub autostart: bool,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct Identity {
    pub id: String,
    pub name: String,
    pub user: String,
    pub key: Option<String>,
    /// password or key passphrase; encrypted with the master key on disk
    #[serde(default)]
    pub secret: String,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct Key {
    pub id: String,
    pub name: String,
    pub file: String,
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Db {
    #[serde(default)]
    pub tunnels: Vec<Tunnel>,
    #[serde(default)]
    pub identities: Vec<Identity>,
    #[serde(default)]
    pub keys: Vec<Key>,
    /// None until a master password is created
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<Vault>,
    /// master key; None while locked
    #[serde(skip)]
    key: Option<[u8; 32]>,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct Vault {
    salt: String,
    /// CHECK encrypted with the master key, proves a typed password is right
    check: String,
    /// master key sealed with DPAPI when "remember on this computer" is on
    #[serde(default)]
    remember: String,
}

const CHECK: &str = "munnel-vault";

pub fn new_id() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    format!("{:08x}", (t as u32) ^ N.fetch_add(0x9e37_79b9, Ordering::Relaxed))
}

pub fn data_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("MUNNEL_DATA") {
        return d.into();
    }
    documents().join("Munnel")
}

/// The user's Documents folder (follows OneDrive / folder redirection).
fn documents() -> PathBuf {
    #[cfg(windows)]
    if let Some(p) = known_folder::documents() {
        return p;
    }
    std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")).map_or_else(|| ".".into(), PathBuf::from).join("Documents")
}

#[cfg(windows)]
mod known_folder {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStringExt;

    #[repr(C)]
    struct Guid(u32, u16, u16, [u8; 8]);
    const DOCUMENTS: Guid = Guid(0xFDD39AD0, 0x238F, 0x46AF, [0xAD, 0xB4, 0x6C, 0x85, 0x48, 0x03, 0x69, 0xC7]);

    #[link(name = "shell32")]
    unsafe extern "system" {
        fn SHGetKnownFolderPath(id: *const Guid, flags: u32, token: *mut c_void, path: *mut *mut u16) -> i32;
    }
    #[link(name = "ole32")]
    unsafe extern "system" {
        fn CoTaskMemFree(p: *mut c_void);
    }

    pub fn documents() -> Option<std::path::PathBuf> {
        let mut p = std::ptr::null_mut();
        // SAFETY: p receives a NUL-terminated wide string that we free with CoTaskMemFree, as the API requires (even on failure).
        unsafe {
            let hr = SHGetKnownFolderPath(&DOCUMENTS, 0, std::ptr::null_mut(), &mut p);
            let out = (hr == 0 && !p.is_null()).then(|| {
                let len = (0..).take_while(|&i| *p.add(i) != 0).count();
                std::ffi::OsString::from_wide(std::slice::from_raw_parts(p, len)).into()
            });
            CoTaskMemFree(p.cast());
            out
        }
    }
}

/// Older builds kept data next to the exe in data\; copy it over once.
fn migrate() {
    let new = data_dir();
    let Some(old) = std::env::current_exe().ok().and_then(|p| p.parent().map(|p| p.join("data"))) else { return };
    if std::env::var_os("MUNNEL_DATA").is_some() || new.join("munnel.json").exists() || !old.join("munnel.json").exists() {
        return;
    }
    let _ = std::fs::create_dir_all(new.join("keys"));
    for (from, to) in [(old.clone(), new.clone()), (old.join("keys"), new.join("keys"))] {
        for f in std::fs::read_dir(&from).into_iter().flatten().flatten().filter(|f| f.path().is_file()) {
            if std::fs::copy(f.path(), to.join(f.file_name())).is_ok() && from.ends_with("keys") {
                lock(&to.join(f.file_name()));
            }
        }
    }
}

pub fn keys_dir() -> PathBuf {
    data_dir().join("keys")
}

impl Db {
    /// Secrets stay encrypted until `unlock`. Data from before the master password (DPAPI / plain) is readable right away.
    pub fn load() -> Db {
        migrate();
        let mut db: Db = std::fs::read_to_string(data_dir().join("munnel.json"))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        if db.vault.is_none() {
            for i in &mut db.identities {
                i.secret = unseal(&i.secret);
            }
        }
        db
    }

    /// True while the master password still has to be typed (or created).
    pub fn locked(&self) -> bool {
        self.key.is_none()
    }

    /// Unlocks with the key remembered via DPAPI, if any.
    pub fn unlock_saved(&mut self) -> bool {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let Some(v) = &self.vault else { return false };
        let key = STANDARD.decode(unseal(&v.remember)).ok().and_then(|k| <[u8; 32]>::try_from(k).ok());
        key.is_some_and(|k| self.open_with(k))
    }

    pub fn unlock(&mut self, master: &str) -> bool {
        let Some(v) = &self.vault else { return false };
        derive(master, &v.salt).is_some_and(|k| self.open_with(k))
    }

    fn open_with(&mut self, key: [u8; 32]) -> bool {
        let Some(v) = &self.vault else { return false };
        if decrypt(&key, &v.check).as_deref() != Some(CHECK) {
            return false;
        }
        for i in &mut self.identities {
            i.secret = match i.secret.starts_with("enc:") {
                true => decrypt(&key, &i.secret).unwrap_or_default(),
                false => unseal(&i.secret),
            };
        }
        self.key = Some(key);
        true
    }

    /// Creates or changes the master password and re-encrypts everything. Only call while unlocked or before the first master.
    pub fn set_master(&mut self, master: &str, remember: bool) -> std::io::Result<()> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|e| std::io::Error::other(e.to_string()))?;
        let salt = STANDARD.encode(salt);
        let key = derive(master, &salt).ok_or_else(|| std::io::Error::other("key derivation failed"))?;
        let sealed = seal(&STANDARD.encode(key));
        let remember = if remember && sealed.starts_with("dpapi:") { sealed } else { String::new() };
        self.vault = Some(Vault { check: encrypt(&key, CHECK), salt, remember });
        self.key = Some(key);
        self.save()
    }

    pub fn remembers(&self) -> bool {
        self.vault.as_ref().is_some_and(|v| !v.remember.is_empty())
    }

    /// Forgotten master password: drops every saved password so a new master can be created. Tunnels and keys stay.
    pub fn reset_master(&mut self) {
        for i in &mut self.identities {
            i.secret.clear();
        }
        self.vault = None;
        self.key = None;
    }

    pub fn save(&self) -> std::io::Result<()> {
        let key = self.key.ok_or_else(|| std::io::Error::other("locked: master password not entered"))?;
        std::fs::create_dir_all(keys_dir())?;
        let mut out = Db { tunnels: self.tunnels.clone(), identities: self.identities.clone(), keys: self.keys.clone(), vault: self.vault.clone(), key: None };
        for i in out.identities.iter_mut().filter(|i| !i.secret.is_empty()) {
            i.secret = encrypt(&key, &i.secret);
        }
        let f = data_dir().join("munnel.json");
        let tmp = f.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&out)?)?;
        std::fs::rename(tmp, f)
    }

    pub fn identity(&self, id: &str) -> Option<&Identity> {
        self.identities.iter().find(|i| i.id == id)
    }

    pub fn key(&self, id: &str) -> Option<&Key> {
        self.keys.iter().find(|k| k.id == id)
    }
}

// ---- secrets: master key (Argon2id + AES-256-GCM)

fn derive(master: &str, salt: &str) -> Option<[u8; 32]> {
    let mut k = [0u8; 32];
    argon2::Argon2::default().hash_password_into(master.as_bytes(), salt.as_bytes(), &mut k).ok()?;
    Some(k)
}

/// "enc:" + base64(nonce || ciphertext+tag)
fn encrypt(key: &[u8; 32], plain: &str) -> String {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use base64::{Engine, engine::general_purpose::STANDARD};
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).expect("OS random generator");
    let ct = Aes256Gcm::new(key.into()).encrypt(&nonce.into(), plain.as_bytes()).expect("AES-GCM encrypt");
    format!("enc:{}", STANDARD.encode([&nonce[..], &ct].concat()))
}

fn decrypt(key: &[u8; 32], s: &str) -> Option<String> {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use base64::{Engine, engine::general_purpose::STANDARD};
    let raw = STANDARD.decode(s.strip_prefix("enc:")?).ok()?;
    let (nonce, ct) = raw.split_at_checked(12)?;
    let pt = Aes256Gcm::new(key.into()).decrypt(<&[u8; 12]>::try_from(nonce).ok()?.into(), ct).ok()?;
    String::from_utf8(pt).ok()
}

// ---- Windows DPAPI (this Windows user only): legacy secrets + remembered master key

#[cfg(windows)]
mod dpapi {
    use std::ffi::c_void;

    #[repr(C)]
    struct Blob {
        cb: u32,
        pb: *mut u8,
    }

    #[link(name = "crypt32")]
    unsafe extern "system" {
        fn CryptProtectData(i: *const Blob, d: *const u16, e: *const Blob, r: *const c_void, p: *const c_void, f: u32, o: *mut Blob) -> i32;
        fn CryptUnprotectData(i: *const Blob, d: *mut c_void, e: *const Blob, r: *const c_void, p: *const c_void, f: u32, o: *mut Blob) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LocalFree(h: *mut c_void) -> *mut c_void;
    }

    pub fn run(data: &[u8], protect: bool) -> Option<Vec<u8>> {
        let src = Blob { cb: data.len() as u32, pb: data.as_ptr() as *mut u8 };
        let mut out = Blob { cb: 0, pb: std::ptr::null_mut() };
        let np = std::ptr::null();
        // SAFETY: src/out are valid Blobs for the duration of the call; out.pb is freed with LocalFree as the API requires.
        unsafe {
            let ok = if protect {
                CryptProtectData(&src, std::ptr::null(), np, np.cast(), np.cast(), 0, &mut out)
            } else {
                CryptUnprotectData(&src, std::ptr::null_mut(), np, np.cast(), np.cast(), 0, &mut out)
            };
            if ok == 0 {
                return None;
            }
            let v = std::slice::from_raw_parts(out.pb, out.cb as usize).to_vec();
            LocalFree(out.pb.cast());
            Some(v)
        }
    }
}

pub fn seal(s: &str) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    #[cfg(windows)]
    if !s.is_empty() {
        if let Some(b) = dpapi::run(s.as_bytes(), true) {
            return format!("dpapi:{}", STANDARD.encode(b));
        }
    }
    s.to_string() // ponytail: plaintext off Windows / on DPAPI failure, use a keyring crate if this ships elsewhere
}

pub fn unseal(s: &str) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let Some(b) = s.strip_prefix("dpapi:") else { return s.to_string() }; // legacy plaintext: re-sealed on next save
    #[cfg(windows)]
    if let Some(v) = STANDARD.decode(b).ok().and_then(|raw| dpapi::run(&raw, false)) {
        return String::from_utf8_lossy(&v).into_owned();
    }
    let _ = (b, &STANDARD);
    String::new() // sealed by another Windows user
}

// ---- ssh

/// Arguments for `ssh`. `key` is a private key path, `known_hosts` the app-local known_hosts file. Secret goes via SSH_ASKPASS env (see run.rs), never argv.
pub fn ssh_args(t: &Tunnel, ident: &Identity, key: Option<&Path>, known_hosts: &Path) -> Vec<String> {
    let mut a: Vec<String> = ["-N", "-p"].map(String::from).into();
    a.push(t.ssh_port.to_string());
    for o in [
        "ExitOnForwardFailure=yes",
        "ServerAliveInterval=30",
        "ConnectTimeout=15",
        "StrictHostKeyChecking=accept-new",
        "NumberOfPasswordPrompts=1",
    ] {
        a.extend(["-o".into(), o.into()]);
    }
    a.extend(["-o".into(), format!("UserKnownHostsFile={}", known_hosts.display())]); // host keys stay in data/, not ~/.ssh
    if let Some(k) = key {
        a.extend(["-i".into(), k.display().to_string(), "-o".into(), "IdentitiesOnly=yes".into()]);
    }
    if ident.secret.is_empty() {
        a.extend(["-o".into(), "BatchMode=yes".into()]); // nothing to answer a prompt with
    }
    let (p, h, d) = (t.listen_port, &t.dest_host, t.dest_port);
    match t.kind {
        Kind::Local => a.extend(["-L".into(), format!("{p}:{h}:{d}")]),
        Kind::Remote => a.extend(["-R".into(), format!("{p}:{h}:{d}")]),
        Kind::Dynamic => a.extend(["-D".into(), p.to_string()]),
    }
    a.push(format!("{}@{}", ident.user, t.ssh_host));
    a
}

pub fn command(program: &str) -> Command {
    let mut c = Command::new(program);
    #[cfg(windows)]
    std::os::windows::process::CommandExt::creation_flags(&mut c, 0x0800_0000); // CREATE_NO_WINDOW
    c
}

// ---- keys

/// ssh refuses private keys that other users can read.
pub fn lock(path: &Path) {
    #[cfg(windows)]
    {
        let user = std::env::var("USERNAME").unwrap_or_default();
        let _ = command("icacls").arg(path).args(["/inheritance:r", "/grant:r", &format!("{user}:F")]).output();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

/// Unused filename in data/keys for `name`.
pub fn new_key_file(name: &str) -> String {
    let base: String = name.chars().map(|c| if c.is_alphanumeric() || "-_.".contains(c) { c } else { '_' }).collect();
    let base = if base.is_empty() { "key".into() } else { base };
    let dir = keys_dir();
    let mut f = base.clone();
    let mut n = 1;
    while dir.join(&f).exists() || dir.join(format!("{f}.pub")).exists() {
        n += 1;
        f = format!("{base}_{n}");
    }
    f
}

pub fn generate_key(db: &mut Db, name: &str, kind: &str, passphrase: &str) -> Result<(), String> {
    std::fs::create_dir_all(keys_dir()).map_err(|e| e.to_string())?;
    let file = new_key_file(name);
    let path = keys_dir().join(&file);
    let mut c = command("ssh-keygen");
    c.args(["-q", "-t", kind, "-f"]).arg(&path).args(["-N", passphrase, "-C", name]);
    if kind == "rsa" {
        c.args(["-b", "4096"]);
    }
    let out = c.output().map_err(|e| format!("cannot run ssh-keygen: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    lock(&path);
    db.keys.push(Key { id: new_id(), name: name.into(), file });
    Ok(())
}

pub fn import_key(db: &mut Db, src: &Path, name: &str) -> Result<(), String> {
    std::fs::create_dir_all(keys_dir()).map_err(|e| e.to_string())?;
    let file = new_key_file(name);
    let dst = keys_dir().join(&file);
    std::fs::copy(src, &dst).map_err(|e| e.to_string())?;
    let mut pub_src = src.as_os_str().to_owned();
    pub_src.push(".pub");
    let _ = std::fs::copy(&pub_src, keys_dir().join(format!("{file}.pub")));
    lock(&dst);
    db.keys.push(Key { id: new_id(), name: name.into(), file });
    Ok(())
}

pub fn pubkey(path: &Path) -> Option<String> {
    let mut p = path.as_os_str().to_owned();
    p.push(".pub");
    if let Ok(s) = std::fs::read_to_string(&p) {
        return Some(s.trim().to_string());
    }
    let o = command("ssh-keygen").args(["-y", "-P", "", "-f"]).arg(path).output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tun(kind: Kind) -> Tunnel {
        Tunnel {
            kind,
            listen_port: 15434,
            dest_host: "10.233.16.103".into(),
            dest_port: 30434,
            ssh_host: "171.244.195.103".into(),
            ssh_port: 2222,
            ..Default::default()
        }
    }

    #[test]
    fn args() {
        let root = Identity { user: "root".into(), ..Default::default() };
        let a = ssh_args(&tun(Kind::Local), &root, Some(Path::new("k")), Path::new("kh"));
        assert_eq!(a.last().unwrap(), "root@171.244.195.103");
        assert!(a.contains(&"15434:10.233.16.103:30434".into()) && a.contains(&"-i".into()) && a.contains(&"BatchMode=yes".into()));
        let pw = Identity { user: "root".into(), secret: "x".into(), ..Default::default() };
        assert!(!ssh_args(&tun(Kind::Local), &pw, None, Path::new("kh")).contains(&"BatchMode=yes".into()));
        assert!(ssh_args(&tun(Kind::Remote), &root, None, Path::new("kh")).windows(2).any(|w| w == ["-R", "15434:10.233.16.103:30434"]));
        assert!(ssh_args(&tun(Kind::Dynamic), &root, None, Path::new("kh")).windows(2).any(|w| w == ["-D", "15434"]));
    }

    #[test]
    fn secrets() {
        let s = "p@ss&%^ wörd";
        let sealed = seal(s);
        assert_eq!(unseal(&sealed), s);
        #[cfg(windows)]
        assert!(sealed.starts_with("dpapi:") && !sealed.contains("ss&"));
        assert_eq!(unseal("plain"), "plain");
        assert_eq!(seal(""), "");
    }

    #[test]
    fn master() {
        let mut db = Db { identities: vec![Identity { id: "i".into(), secret: "p@ss wörd".into(), ..Default::default() }], ..Default::default() };
        assert!(db.locked() && db.save().is_err());
        let dir = std::env::temp_dir().join(format!("munnel-master-{}", std::process::id()));
        // SAFETY: only this test reads MUNNEL_DATA in the unit-test binary.
        unsafe { std::env::set_var("MUNNEL_DATA", &dir) };
        db.set_master("m4ster", false).unwrap();
        let raw = std::fs::read_to_string(dir.join("munnel.json")).unwrap();
        assert!(raw.contains("\"enc:") && !raw.contains("ss w"));
        let mut back = Db::load();
        assert!(back.locked() && !back.unlock_saved() && !back.unlock("wrong") && back.identities[0].secret.starts_with("enc:"));
        assert!(back.unlock("m4ster") && back.identities[0].secret == "p@ss wörd");
        back.set_master("new", true).unwrap();
        let mut again = Db::load();
        #[cfg(windows)]
        assert!(again.unlock_saved() && again.identities[0].secret == "p@ss wörd");
        again.reset_master();
        assert!(again.vault.is_none() && again.identities[0].secret.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn json_roundtrip() {
        let j = r#"{"tunnels":[{"id":"a","type":"dynamic","name":"n","listen_port":1080,"ssh_port":22,"ssh_host":"h","identity":"i"}],"identities":[{"id":"i","name":"x","user":"u","key":null,"secret":""}],"keys":[]}"#;
        let db: Db = serde_json::from_str(j).unwrap();
        assert_eq!(db.tunnels[0].kind, Kind::Dynamic);
        assert!(serde_json::to_string(&db).unwrap().contains(r#""type":"dynamic""#));
    }
}
