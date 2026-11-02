# Munnel

**English** | [Tiếng Việt](README.vi.md)

SSH tunnel manager for Windows. Written in Rust + egui (wgpu renderer).
Each tunnel runs as one OpenSSH `ssh -N` process. Munnel reconnects tunnels that drop.

## Features

- 3 tunnel types: **Local** (`-L`), **Remote** (`-R`), **Dynamic** (`-D`, SOCKS5 proxy).
- Start/stop one tunnel or all tunnels; start tunnels when the app opens (`Start when Munnel opens`).
- Automatic reconnect when a stable tunnel drops.
- Identity management (user + key + password/passphrase) and SSH key management (generate, import, copy public key, delete).
- Saved passwords are encrypted with a master password (Argon2id + AES-256-GCM).
- Suggests previously connected SSH servers when you create a new tunnel.
- Light and dark theme.

## Requirements

- Windows 10/11 (64-bit).
- OpenSSH client: `ssh.exe` and `ssh-keygen.exe` on `PATH`. Windows 10 1809+ includes it (Optional Features → OpenSSH Client).
- No extra runtime: the build links the CRT statically (no `vcruntime140.dll` needed).

## Installation

Download `munnel-<version>-win64.zip`, extract it, and run `munnel.exe`.

Build from source:

```sh
cargo build --release
# output: target/release/munnel.exe
```

The project uses `sccache` as `rustc-wrapper` (see `.cargo/config.toml`). If sccache is not installed, install it (`cargo install sccache`) or remove the `rustc-wrapper` line.

## Usage

### 1. Master password

On first launch, create a master password. It encrypts all saved passwords and passphrases.

- **Remember on this computer**: stores the master key with Windows DPAPI. The app unlocks itself at startup, for the current Windows user only.
- Forgot the master password: click **Forgot master password?** → **Reset**. This deletes all saved passwords and passphrases. Tunnels, identities and keys stay.
- Change the master password: **Master password** button in the bottom bar.

### 2. Create an identity

**Identities & keys** → **Identities** tab → **New identity**:

| Field | Meaning |
|---|---|
| Name | Display name |
| Username | SSH user on the server |
| Private key | Key used to log in, or `(none - password / agent)` |
| Password / key passphrase | SSH password, or the key passphrase. Leave empty for a key without a passphrase |

An identity without a password runs `ssh` with `BatchMode=yes`: it never prompts for a password.

### 3. SSH keys

**SSH keys** tab:

- **Generate...**: creates an `ed25519` or `rsa 4096` key with `ssh-keygen`.
- **Import...**: copies an existing private key (usually from `%USERPROFILE%\.ssh`) into the app data folder. A `.pub` file with the same name is copied too, if present.
- **Copy public key**: copies the public key to the clipboard. Append it to `~/.ssh/authorized_keys` on the server.

Generated and imported keys get locked permissions via `icacls` (readable by the current user only). `ssh` refuses keys that other users can read.

You cannot delete a key that an identity uses, or an identity that a tunnel uses.

### 4. Create a tunnel

**New SSH tunnel**, then pick a type:

| Type | Fields | Result |
|---|---|---|
| Local | Local listen port, Remote server host/port | `localhost:<listen>` on your machine reaches `host:port` (as seen from the SSH server) |
| Remote | Port on SSH server, Local destination host/port | `localhost:<port>` on the SSH server reaches `host:port` (as seen from your machine) |
| Dynamic | Local SOCKS port | SOCKS5 proxy at `localhost:<port>` |

Then fill in the SSH server host/port and pick an identity. The blue text below the form describes what the tunnel does.

Editing a running tunnel restarts it to apply the changes. To rename quickly, edit the Name cell in the table.

### 5. Status

| Status | Meaning |
|---|---|
| `stopped` | Not running |
| `running` | The `ssh` process is alive |
| `error: ...` | `ssh` exited before the tunnel became stable (wrong password, port in use, wrong host...). No retry |
| `reconnecting... (...)` | The tunnel was stable, then dropped. The app retries every 5 seconds |

A tunnel counts as "stable" after 15 seconds of continuous uptime. A failure before that is treated as a config or auth error, so the app does not retry. The error text is the last stderr line from `ssh`; hover over it to see all of it.

## Data

Data folder: `Documents\Munnel` (follows OneDrive / folder redirection). Set the `MUNNEL_DATA` environment variable to use a different folder.

| File | Contents |
|---|---|
| `munnel.json` | Tunnels, identities, keys, recent servers, settings. Passwords are stored as `enc:...` |
| `keys\` | Private/public keys |
| `known_hosts` | Server host keys, separate from `~/.ssh/known_hosts` |
| `askpass.cmd` | Helper that lets `ssh` get the password (see below) |

Older builds stored data in `data\` next to `munnel.exe`. On first run, the app copies it to the new folder if the new folder has no `munnel.json`.

Backup: copy the whole `Documents\Munnel` folder. You need the master password to read the passwords in a backup.

## Security

- Passwords/passphrases: AES-256-GCM, with the key derived from the master password by Argon2id (random salt). The master password is not stored anywhere.
- "Remember on this computer" stores the master key with DPAPI. Anyone who can log in as that Windows user can open the app.
- Passwords never appear on a command line. `ssh` calls `askpass.cmd` (via `SSH_ASKPASS`), which runs `munnel.exe --askpass`. That command prints the password from the `MUNNEL_SECRET` environment variable of the child `ssh` process.
- Host keys: `StrictHostKeyChecking=accept-new`. On first connect, the host key is trusted and saved. If the host key changes later, `ssh` refuses to connect. If the server changed its key legitimately, delete the matching line in `Documents\Munnel\known_hosts`.

Fixed `ssh` options: `ExitOnForwardFailure=yes`, `ServerAliveInterval=30`, `ConnectTimeout=15`, `NumberOfPasswordPrompts=1`, `IdentitiesOnly=yes` (when a key is set).

## Development

```
src/
  main.rs   entry point; handles --askpass
  ui.rs     egui UI: tunnel table, dialogs, master password
  run.rs    Runner: spawns ssh, tracks state, reconnects
  store.rs  data model, JSON persistence, encryption, DPAPI, ssh arguments, key management
tests/
  e2e.rs    end-to-end tests with real ssh and an in-process russh server
```

Run tests:

```sh
cargo test --lib          # unit tests: ssh arguments, encryption, master password, JSON
cargo test --test e2e     # needs ssh and ssh-keygen on PATH
```

The e2e test sets `MUNNEL_DATA` to a temp folder, so it does not touch real data. `MUNNEL_EXE` points askpass at the real `munnel` binary instead of the test harness.

## Limitations

- Windows only: askpass uses a `.cmd` file, and "remember" uses DPAPI.
- No jump host (`ProxyJump`) field. `ssh` still reads `~/.ssh/config`, so you can set `ProxyJump` there for the matching host. Arguments the app passes (`-p`, `user@host`, `-o ...`) take precedence over the config.
