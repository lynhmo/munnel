//! Runs one `ssh -N` process per tunnel, tracks state, reconnects dropped tunnels.
use crate::store::{self, Db, Tunnel};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::process::{Child, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Reconnect delay, and uptime after which a drop counts as a network drop rather than a config/auth error.
const RETRY: Duration = Duration::from_secs(5);
const STABLE: Duration = Duration::from_secs(15);

#[derive(Clone, PartialEq, Debug)]
pub enum State {
    Stopped,
    Running,
    Error(String),
    Reconnecting(String),
}

struct Run {
    child: Option<Child>,
    log: Arc<Mutex<Vec<String>>>,
    t0: Instant,
    /// was up once -> reconnect when it drops
    ok: bool,
    retry_at: Option<Instant>,
    exit: Option<String>,
}

impl Run {
    fn alive(&mut self) -> bool {
        let Some(c) = &mut self.child else { return false };
        match c.try_wait() {
            Ok(None) => true,
            r => {
                self.exit = Some(match r {
                    Ok(Some(s)) => format!("ssh exited ({s})"),
                    _ => "ssh lost".into(),
                });
                self.child = None;
                false
            }
        }
    }

    fn last_msg(&self) -> String {
        self.log.lock().ok().and_then(|l| l.last().cloned()).or_else(|| self.exit.clone()).unwrap_or_else(|| "failed".into())
    }
}

#[derive(Default)]
pub struct Runner {
    runs: HashMap<String, Run>,
}

impl Runner {
    pub fn start(&mut self, db: &Db, t: &Tunnel, ok: bool) {
        if self.runs.get_mut(&t.id).is_some_and(Run::alive) {
            return;
        }
        let run = match spawn(db, t) {
            Ok((child, log)) => Run { child: Some(child), log, t0: Instant::now(), ok, retry_at: None, exit: None },
            Err(e) => Run { child: None, log: Arc::new(Mutex::new(vec![e])), t0: Instant::now(), ok: false, retry_at: None, exit: None },
        };
        self.runs.insert(t.id.clone(), run);
    }

    pub fn stop(&mut self, id: &str) {
        if let Some(mut r) = self.runs.remove(id) {
            if let Some(c) = &mut r.child {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }

    pub fn stop_all(&mut self) {
        let ids: Vec<_> = self.runs.keys().cloned().collect();
        for id in ids {
            self.stop(&id);
        }
    }

    /// Simulates the connection dropping (tests): kills ssh but keeps the tunnel registered so it can reconnect.
    pub fn drop_connection(&mut self, id: &str) {
        if let Some(c) = self.runs.get_mut(id).and_then(|r| r.child.as_mut()) {
            let _ = c.kill();
        }
    }

    pub fn state(&mut self, id: &str) -> State {
        let Some(r) = self.runs.get_mut(id) else { return State::Stopped };
        if r.alive() {
            State::Running
        } else if r.ok {
            State::Reconnecting(r.last_msg())
        } else {
            State::Error(r.last_msg())
        }
    }

    /// Call about once a second.
    pub fn tick(&mut self, db: &Db) {
        let now = Instant::now();
        let mut again = vec![];
        for t in &db.tunnels {
            let Some(r) = self.runs.get_mut(&t.id) else { continue };
            if r.alive() {
                r.ok |= now - r.t0 > STABLE;
            } else if r.ok {
                let at = *r.retry_at.get_or_insert(now + RETRY);
                if now >= at {
                    again.push(t.clone());
                }
            }
        }
        for t in again {
            self.start(db, &t, true);
        }
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        self.stop_all();
    }
}

fn spawn(db: &Db, t: &Tunnel) -> Result<(Child, Arc<Mutex<Vec<String>>>), String> {
    let ident = db.identity(&t.identity).ok_or("identity missing")?;
    let key = ident.key.as_deref().and_then(|k| db.key(k)).map(|k| store::keys_dir().join(&k.file));
    let mut c = store::command("ssh");
    std::fs::create_dir_all(store::data_dir()).map_err(|e| e.to_string())?;
    c.args(store::ssh_args(t, ident, key.as_deref(), &store::data_dir().join("known_hosts"))).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    if !ident.secret.is_empty() {
        c.env("SSH_ASKPASS", askpass()?)
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env("DISPLAY", "munnel")
            .env("MUNNEL_SECRET", &ident.secret);
    }
    let mut child = c.spawn().map_err(|e| format!("cannot run ssh: {e}"))?;
    let log = Arc::new(Mutex::new(Vec::new()));
    let (err, sink) = (child.stderr.take().ok_or("no stderr")?, log.clone());
    std::thread::spawn(move || {
        for line in BufReader::new(err).lines().map_while(Result::ok) {
            if let (false, Ok(mut l)) = (line.trim().is_empty(), sink.lock()) {
                l.push(line.trim().to_string());
            }
        }
    });
    Ok((child, log))
}

/// ssh runs this helper to get the password/passphrase. It is munnel itself (`--askpass`), reading the secret from env,
/// so the secret never goes through cmd.exe parsing or the command line.
fn askpass() -> Result<std::path::PathBuf, String> {
    let exe: std::path::PathBuf = match std::env::var_os("MUNNEL_EXE") {
        Some(e) => e.into(), // lets tests point at the real binary instead of the test harness
        None => std::env::current_exe().map_err(|e| e.to_string())?,
    };
    let f = store::data_dir().join("askpass.cmd");
    std::fs::create_dir_all(store::data_dir()).map_err(|e| e.to_string())?;
    std::fs::write(&f, format!("@\"{}\" --askpass\r\n", exe.display())).map_err(|e| e.to_string())?;
    Ok(f)
}
