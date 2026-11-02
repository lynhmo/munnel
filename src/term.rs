//! Shell for the terminal drawer: Windows PowerShell on pipes. With -NoExit it still prints its prompt and echoes each
//! command, so the output reads like a console.
// ponytail: pipes, not a pseudo-console - full-screen/TTY programs (vim, top, ssh password prompts) won't work; ConPTY + a VT parser if needed.
use crate::store;
use std::io::{Read, Write};
use std::process::{Child, ChildStdin, Stdio};
use std::sync::{Arc, Mutex};

/// Keep the last ~256 KB of output.
const MAX: usize = 256 * 1024;

pub struct Term {
    child: Child,
    stdin: ChildStdin,
    pub out: Arc<Mutex<String>>,
}

impl Term {
    pub fn spawn(ctx: &eframe::egui::Context) -> Result<Self, String> {
        let home = std::env::var_os("USERPROFILE").unwrap_or_else(|| ".".into());
        let mut child = store::command("powershell.exe")
            .args(["-NoLogo", "-NoExit", "-Command", "[Console]::InputEncoding=[Console]::OutputEncoding=[Text.Encoding]::UTF8"])
            .current_dir(home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot run powershell: {e}"))?;
        let out = Arc::new(Mutex::new(String::new()));
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let pipes: [Box<dyn Read + Send>; 2] = [Box::new(child.stdout.take().ok_or("no stdout")?), Box::new(child.stderr.take().ok_or("no stderr")?)];
        for mut p in pipes {
            let (out, ctx) = (out.clone(), ctx.clone());
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n @ 1..) = p.read(&mut buf) {
                    if let Ok(mut o) = out.lock() {
                        push(&mut o, &String::from_utf8_lossy(&buf[..n]));
                    }
                    ctx.request_repaint();
                }
            });
        }
        Ok(Self { child, stdin, out })
    }

    pub fn send(&mut self, line: &str) {
        if self.stdin.write_all(format!("{line}\r\n").as_bytes()).is_err() {
            if let Ok(mut o) = self.out.lock() {
                push(&mut o, "\n[shell exited - press Restart]\n");
            }
        }
    }
}

impl Drop for Term {
    fn drop(&mut self) {
        // /T: also ends ssh etc. started from the shell
        let _ = store::command("taskkill").args(["/T", "/F", "/PID", &self.child.id().to_string()]).output();
        let _ = self.child.wait();
    }
}

fn push(o: &mut String, s: &str) {
    o.push_str(&s.replace('\r', ""));
    if o.len() > MAX {
        let mut cut = o.len() - MAX;
        while !o.is_char_boundary(cut) {
            cut += 1;
        }
        o.drain(..cut);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_strips_cr_and_caps_on_char_boundary() {
        let mut o = String::new();
        push(&mut o, "a\r\nb");
        assert_eq!(o, "a\nb");
        push(&mut o, &"é".repeat(MAX));
        assert!(o.len() <= MAX && o.ends_with('é'));
    }

    #[test]
    fn shell_runs_commands() {
        let mut t = Term::spawn(&eframe::egui::Context::default()).unwrap();
        t.send("echo munnel-ok");
        for _ in 0..50 {
            if t.out.lock().unwrap().contains("\nmunnel-ok") {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("no output: {}", t.out.lock().unwrap());
    }
}
