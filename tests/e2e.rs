//! End-to-end: real `ssh` client (via Runner) against an in-process russh server.
//! Needs OpenSSH (`ssh`, `ssh-keygen`) on PATH. Run: `cargo test --test e2e`.
use munnel::run::{Runner, State};
use munnel::store::{self, Db, Identity, Kind, Tunnel};
use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::server::{self, Auth, Msg, Server as _, Session, VerifiedPublicKey};
use russh::Channel;
use std::io::{Read, Write};
use std::net::{TcpListener as StdListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream as TokioStream};

#[derive(Clone)]
struct Srv {
    allowed: Arc<Mutex<Vec<PublicKey>>>,
}

impl server::Server for Srv {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        self.clone()
    }
}

impl server::Handler for Srv {
    type Error = russh::Error;

    async fn auth_password(&mut self, _: &str, pw: &str) -> Result<Auth, Self::Error> {
        Ok(if pw == "pw" { Auth::Accept } else { Auth::reject() })
    }

    async fn auth_publickey(&mut self, _: &str, key: VerifiedPublicKey<'_>) -> Result<Auth, Self::Error> {
        let ok = self.allowed.lock().unwrap().iter().any(|k| k.key_data() == key.public_key.key_data());
        Ok(if ok { Auth::Accept } else { Auth::reject() })
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _: &str,
        _: u32,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        match TokioStream::connect((host, port as u16)).await {
            Ok(mut target) => {
                reply.accept().await;
                tokio::spawn(async move {
                    let _ = copy_bidirectional(&mut channel.into_stream(), &mut target).await;
                });
            }
            Err(_) => drop(reply), // dropping the handle rejects the channel
        }
        Ok(())
    }

    async fn tcpip_forward(&mut self, address: &str, port: &mut u32, session: &mut Session) -> Result<bool, Self::Error> {
        let Ok(listener) = TcpListener::bind(("127.0.0.1", *port as u16)).await else { return Ok(false) };
        let (handle, address, port) = (session.handle(), address.to_string(), *port);
        tokio::spawn(async move {
            while let Ok((mut conn, peer)) = listener.accept().await {
                let (handle, address) = (handle.clone(), address.clone());
                tokio::spawn(async move {
                    if let Ok(ch) = handle.channel_open_forwarded_tcpip(address, port, "127.0.0.1", peer.port() as u32).await {
                        let _ = copy_bidirectional(&mut ch.into_stream(), &mut conn).await;
                    }
                });
            }
        });
        Ok(true)
    }
}

/// Starts the SSH server (password "pw", or any key in `allowed`) and a "hi" -> "echo:hi" server.
/// Returns (ssh port, echo port).
fn start_servers(allowed: Arc<Mutex<Vec<PublicKey>>>) -> (u16, u16) {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        tokio::runtime::Runtime::new().unwrap().block_on(async move {
            let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let ssh = TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send((ssh.local_addr().unwrap().port(), echo.local_addr().unwrap().port())).unwrap();
            tokio::spawn(async move {
                while let Ok((mut c, _)) = echo.accept().await {
                    tokio::spawn(async move {
                        let mut buf = [0u8; 100];
                        if let Ok(n) = c.read(&mut buf).await {
                            let _ = c.write_all(&[b"echo:".as_slice(), &buf[..n]].concat()).await;
                        }
                    });
                }
            });
            let config = Arc::new(server::Config {
                keys: vec![PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()],
                auth_rejection_time: Duration::from_millis(50),
                auth_rejection_time_initial: Some(Duration::ZERO),
                ..Default::default()
            });
            Srv { allowed }.run_on_socket(config, &ssh).await.unwrap();
        })
    });
    rx.recv_timeout(Duration::from_secs(10)).unwrap()
}

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn io_probe(port: u16, send: &[u8]) -> Option<String> {
    let mut c = TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_secs(2)).ok()?;
    c.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    c.write_all(send).ok()?;
    let mut buf = [0u8; 100];
    let n = c.read(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf[..n]).into_owned())
}

fn socks_probe(port: u16, dest: u16) -> Option<String> {
    let mut c = TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_secs(2)).ok()?;
    c.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    c.write_all(&[5, 1, 0]).ok()?;
    let mut r = [0u8; 2];
    c.read_exact(&mut r).ok()?;
    c.write_all(&[&[5, 1, 0, 1, 127, 0, 0, 1][..], &dest.to_be_bytes()].concat()).ok()?;
    let mut rep = [0u8; 10];
    c.read_exact(&mut rep).ok()?;
    if r != [5, 0] || rep[1] != 0 {
        return None;
    }
    c.write_all(b"hi").ok()?;
    let mut buf = [0u8; 100];
    let n = c.read(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf[..n]).into_owned())
}

/// Retry until the tunnel is up (ssh needs a moment to connect and authenticate).
fn eventually<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let end = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(Instant::now() < end, "timed out: {what}");
        std::thread::sleep(Duration::from_millis(300));
    }
}

fn tunnel(id: &str, kind: Kind, listen: u16, dest: u16, ssh: u16, identity: &str) -> Tunnel {
    Tunnel {
        id: id.into(),
        kind,
        name: id.into(),
        listen_port: listen,
        dest_host: if kind == Kind::Dynamic { String::new() } else { "127.0.0.1".into() },
        dest_port: if kind == Kind::Dynamic { 0 } else { dest },
        ssh_host: "127.0.0.1".into(),
        ssh_port: ssh,
        identity: identity.into(),
        autostart: false,
    }
}

fn ident(id: &str, key: Option<&str>, secret: &str) -> Identity {
    Identity { id: id.into(), name: id.into(), user: "u".into(), key: key.map(Into::into), secret: secret.into() }
}

fn authorize(db: &Db, key_name: &str, allowed: &Arc<Mutex<Vec<PublicKey>>>) -> String {
    let k = db.keys.iter().find(|k| k.name == key_name).unwrap();
    let pubtxt = std::fs::read_to_string(store::keys_dir().join(format!("{}.pub", k.file))).unwrap();
    allowed.lock().unwrap().push(PublicKey::from_openssh(pubtxt.trim()).unwrap());
    k.id.clone()
}

#[test]
fn tunnels_end_to_end() {
    let data = std::env::temp_dir().join(format!("munnel-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    // SAFETY: single test in this binary, no other thread touches the environment yet.
    unsafe {
        std::env::set_var("MUNNEL_DATA", &data);
        std::env::set_var("MUNNEL_EXE", env!("CARGO_BIN_EXE_munnel"));
    }
    let allowed = Arc::new(Mutex::new(vec![]));
    let (ssh, echo) = start_servers(allowed.clone());
    let mut db = Db::default();
    let mut runner = Runner::default();

    // password auth goes through the SSH_ASKPASS helper (munnel --askpass)
    db.identities.push(ident("pw", None, "pw"));
    db.identities.push(ident("badpw", None, "nope"));
    let local = free_port();
    db.tunnels.push(tunnel("local-pw", Kind::Local, local, echo, ssh, "pw"));
    runner.start(&db, &db.tunnels[0], false);
    assert_eq!(eventually("local tunnel with password", || io_probe(local, b"hi")), "echo:hi");
    assert_eq!(runner.state("local-pw"), State::Running);
    runner.stop("local-pw");
    assert_eq!(runner.state("local-pw"), State::Stopped);
    assert!(io_probe(local, b"hi").is_none(), "port must close after stop");

    // wrong password -> error with ssh's message, not a silent hang
    db.tunnels.push(tunnel("bad", Kind::Local, free_port(), echo, ssh, "badpw"));
    runner.start(&db, &db.tunnels[1], false);
    let State::Error(msg) = eventually("wrong password error", || matches!(runner.state("bad"), State::Error(_)).then(|| runner.state("bad")))
    else {
        unreachable!()
    };
    assert!(msg.contains("Permission denied"), "{msg}");

    // remote forward: the SSH server listens, traffic comes back to our echo server
    let rport = free_port();
    db.tunnels.push(tunnel("remote", Kind::Remote, rport, echo, ssh, "pw"));
    runner.start(&db, &db.tunnels[2], false);
    assert_eq!(eventually("remote forward", || io_probe(rport, b"hi")), "echo:hi");

    // dynamic forward: SOCKS5 CONNECT to the echo server
    let sport = free_port();
    db.tunnels.push(tunnel("socks", Kind::Dynamic, sport, 0, ssh, "pw"));
    runner.start(&db, &db.tunnels[3], false);
    assert_eq!(eventually("socks proxy", || socks_probe(sport, echo)), "echo:hi");

    // generated key without passphrase
    store::generate_key(&mut db, "plain", "ed25519", "").unwrap();
    let id = authorize(&db, "plain", &allowed);
    db.identities.push(ident("key", Some(&id), ""));
    let kport = free_port();
    db.tunnels.push(tunnel("key", Kind::Local, kport, echo, ssh, "key"));
    runner.start(&db, &db.tunnels[4], false);
    assert_eq!(eventually("key auth", || io_probe(kport, b"hi")), "echo:hi");

    // key with passphrase: ssh asks for it, the SSH_ASKPASS helper answers with the identity's secret
    store::generate_key(&mut db, "locked", "ed25519", "s3cret").unwrap();
    let id = authorize(&db, "locked", &allowed);
    db.identities.push(ident("locked", Some(&id), "s3cret"));
    db.identities.push(ident("locked-bad", Some(&id), "wrong"));
    let pport = free_port();
    db.tunnels.push(tunnel("locked", Kind::Local, pport, echo, ssh, "locked"));
    runner.start(&db, &db.tunnels[5], false);
    assert_eq!(eventually("passphrase key", || io_probe(pport, b"hi")), "echo:hi");
    db.tunnels.push(tunnel("locked-bad", Kind::Local, free_port(), echo, ssh, "locked-bad"));
    runner.start(&db, &db.tunnels[6], false);
    eventually("wrong passphrase error", || matches!(runner.state("locked-bad"), State::Error(_)).then_some(()));

    // a tunnel that was up for a while reconnects by itself after the connection drops
    let end = Instant::now() + Duration::from_secs(17);
    while Instant::now() < end {
        runner.tick(&db);
        std::thread::sleep(Duration::from_millis(500));
    }
    runner.drop_connection("key");
    assert!(matches!(eventually("drop noticed", || matches!(runner.state("key"), State::Reconnecting(_)).then_some(runner.state("key"))), State::Reconnecting(_)));
    assert_eq!(
        eventually("reconnect", || {
            runner.tick(&db);
            io_probe(kport, b"hi")
        }),
        "echo:hi"
    );
    assert_eq!(runner.state("key"), State::Running);

    // public key of a passphrase-protected key: readable via .pub, unreadable without it
    let locked = store::keys_dir().join(&db.keys.iter().find(|k| k.name == "locked").unwrap().file);
    assert!(store::pubkey(&locked).unwrap().starts_with("ssh-ed25519 "));
    std::fs::remove_file(format!("{}.pub", locked.display())).unwrap();
    assert!(store::pubkey(&locked).is_none());

    // import: keeps the chosen name, copies key + .pub
    let src = data.join("outside");
    std::fs::create_dir_all(&src).unwrap();
    let src_key = src.join("id_test");
    let ok = store::command("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(&src_key).status().unwrap().success();
    assert!(ok);
    store::import_key(&mut db, &src_key, "My Imported").unwrap();
    let k = db.keys.last().unwrap();
    assert_eq!(k.name, "My Imported");
    assert!(store::keys_dir().join(&k.file).exists() && store::keys_dir().join(format!("{}.pub", k.file)).exists());

    // persistence: secrets are sealed on disk, restored on load
    db.set_master("master", false).unwrap();
    let raw = std::fs::read_to_string(data.join("munnel.json")).unwrap();
    assert!(!raw.contains("s3cret"), "secret must not be stored in clear text");
    let mut back = Db::load();
    assert!(back.unlock("master"));
    assert_eq!(back.identity("locked").unwrap().secret, "s3cret");

    runner.stop_all();
    drop(runner);
    let _ = std::fs::remove_dir_all(&data);
}
