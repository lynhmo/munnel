# Munnel

[English](README.md) | **Tiếng Việt**

Trình quản lý SSH tunnel cho Windows. Viết bằng Rust + egui (renderer wgpu).
Mỗi tunnel chạy bằng một tiến trình `ssh -N` của OpenSSH. Tunnel rớt mạng thì Munnel tự kết nối lại.

## Tính năng

- 3 loại tunnel: **Local** (`-L`), **Remote** (`-R`), **Dynamic** (`-D`, SOCKS5 proxy).
- Start/Stop từng tunnel hoặc tất cả; tự chạy khi mở app (`Start when Munnel opens`).
- Tự reconnect khi tunnel đang chạy ổn định bị rớt.
- Quản lý identity (user + key + mật khẩu/passphrase) và SSH key (tạo, import, copy public key, xoá).
- Mật khẩu lưu mã hoá bằng master password (Argon2id + AES-256-GCM).
- Gợi ý SSH server đã từng kết nối khi tạo tunnel mới.
- Theme sáng/tối.

## Yêu cầu

- Windows 10/11 (64-bit).
- OpenSSH client: `ssh.exe` và `ssh-keygen.exe` có trong `PATH`. Windows 10 1809+ có sẵn (Optional Features → OpenSSH Client).
- Không cần cài thêm runtime: bản build link CRT tĩnh (không cần `vcruntime140.dll`).

## Cài đặt

Tải `munnel-<version>-win64.zip`, giải nén, chạy `munnel.exe`.

Build từ source:

```sh
cargo build --release
# output: target/release/munnel.exe
```

Project dùng `sccache` làm `rustc-wrapper` (xem `.cargo/config.toml`). Chưa cài sccache thì cài (`cargo install sccache`) hoặc xoá dòng `rustc-wrapper`.

## Hướng dẫn dùng

### 1. Master password

Lần đầu mở app, tạo master password. Master password mã hoá mọi mật khẩu và passphrase đã lưu.

- **Remember on this computer**: lưu master key bằng Windows DPAPI. App tự mở khoá khi khởi động, chỉ với user Windows hiện tại.
- Quên master password: bấm **Forgot master password?** → **Reset**. Thao tác này xoá mọi mật khẩu/passphrase đã lưu. Tunnel, identity và key vẫn giữ.
- Đổi master password: nút **Master password** ở thanh dưới.

### 2. Tạo identity

**Identities & keys** → tab **Identities** → **New identity**:

| Trường | Ý nghĩa |
|---|---|
| Name | Tên hiển thị |
| Username | User SSH trên server |
| Private key | Key dùng để đăng nhập, hoặc `(none - password / agent)` |
| Password / key passphrase | Mật khẩu SSH, hoặc passphrase của key. Để trống nếu key không có passphrase |

Identity không có mật khẩu chạy `ssh` với `BatchMode=yes`: không bao giờ hỏi mật khẩu.

### 3. SSH key

Tab **SSH keys**:

- **Generate...**: tạo key `ed25519` hoặc `rsa 4096` bằng `ssh-keygen`.
- **Import...**: copy private key có sẵn (thường trong `%USERPROFILE%\.ssh`) vào thư mục dữ liệu của app. File `.pub` cùng tên cũng được copy nếu có.
- **Copy public key**: copy public key vào clipboard. Thêm nội dung này vào `~/.ssh/authorized_keys` trên server.

Key import/tạo mới được khoá quyền bằng `icacls` (chỉ user hiện tại đọc được). `ssh` từ chối key mà user khác đọc được.

Không xoá được key đang dùng bởi identity, hoặc identity đang dùng bởi tunnel.

### 4. Tạo tunnel

**New SSH tunnel**, chọn loại:

| Loại | Trường | Kết quả |
|---|---|---|
| Local | Local listen port, Remote server host/port | `localhost:<listen>` trên máy bạn đi tới `host:port` (nhìn từ SSH server) |
| Remote | Port on SSH server, Local destination host/port | `localhost:<port>` trên SSH server đi tới `host:port` (nhìn từ máy bạn) |
| Dynamic | Local SOCKS port | SOCKS5 proxy tại `localhost:<port>` |

Sau đó điền SSH server host/port và chọn identity. Dòng chữ xanh dưới form mô tả tunnel sẽ làm gì.

Sửa tunnel đang chạy: tunnel tự restart để áp dụng thay đổi. Đổi tên nhanh: sửa trực tiếp ô Name trong bảng.

### 5. Trạng thái

| Trạng thái | Ý nghĩa |
|---|---|
| `stopped` | Chưa chạy |
| `running` | Tiến trình `ssh` đang sống |
| `error: ...` | `ssh` thoát trước khi chạy ổn định (sai mật khẩu, port bị chiếm, host sai...). Không tự thử lại |
| `reconnecting... (...)` | Tunnel đã chạy ổn định rồi bị rớt. App thử lại mỗi 5 giây |

Tunnel tính là "ổn định" sau 15 giây chạy liên tục. Lỗi trước mốc này coi là lỗi cấu hình/xác thực, nên không retry. Thông báo lỗi là dòng stderr cuối cùng của `ssh`; rê chuột vào để xem đủ.

## Dữ liệu

Thư mục dữ liệu: `Documents\Munnel` (theo OneDrive/folder redirection). Đặt biến môi trường `MUNNEL_DATA` để dùng thư mục khác.

| File | Nội dung |
|---|---|
| `munnel.json` | Tunnel, identity, key, server gần đây, cài đặt. Mật khẩu lưu dạng `enc:...` |
| `keys\` | Private/public key |
| `known_hosts` | Host key của server, tách riêng khỏi `~/.ssh/known_hosts` |
| `askpass.cmd` | Helper tạm để `ssh` lấy mật khẩu (xem bên dưới) |

Bản cũ lưu dữ liệu ở `data\` cạnh `munnel.exe`. Lần chạy đầu, app tự copy sang thư mục mới nếu thư mục mới chưa có `munnel.json`.

Sao lưu: copy cả thư mục `Documents\Munnel`. Cần master password để đọc mật khẩu trong bản sao lưu.

## Bảo mật

- Mật khẩu/passphrase: AES-256-GCM, key dẫn xuất từ master password bằng Argon2id (salt ngẫu nhiên). Master password không lưu ở đâu.
- "Remember on this computer" lưu master key bằng DPAPI. Bất kỳ ai đăng nhập được user Windows đó đều mở được app.
- Mật khẩu không bao giờ nằm trên command line. `ssh` gọi `askpass.cmd` (qua `SSH_ASKPASS`), file này chạy `munnel.exe --askpass`. Lệnh đó in mật khẩu từ biến môi trường `MUNNEL_SECRET` của tiến trình `ssh` con.
- Host key: `StrictHostKeyChecking=accept-new`. Lần đầu kết nối, host key được tin và lưu lại. Lần sau host key khác thì `ssh` từ chối. Nếu server đổi key hợp lệ, xoá dòng tương ứng trong `Documents\Munnel\known_hosts`.

Tuỳ chọn `ssh` cố định: `ExitOnForwardFailure=yes`, `ServerAliveInterval=30`, `ConnectTimeout=15`, `NumberOfPasswordPrompts=1`, `IdentitiesOnly=yes` (khi có key).

## Phát triển

```
src/
  main.rs   entry point; xử lý --askpass
  ui.rs     giao diện egui: bảng tunnel, dialog, master password
  run.rs    Runner: spawn ssh, theo dõi trạng thái, reconnect
  store.rs  model dữ liệu, lưu JSON, mã hoá, DPAPI, build tham số ssh, quản lý key
tests/
  e2e.rs    test end-to-end với ssh thật và server russh trong tiến trình
```

Chạy test:

```sh
cargo test --lib          # unit test: tham số ssh, mã hoá, master password, JSON
cargo test --test e2e     # cần ssh và ssh-keygen trong PATH
```

Test e2e đặt `MUNNEL_DATA` sang thư mục tạm, nên không đụng dữ liệu thật. `MUNNEL_EXE` trỏ askpass về binary `munnel` thật thay cho test harness.

## Giới hạn

- Chỉ hỗ trợ Windows: askpass dùng file `.cmd`, mã hoá "remember" dùng DPAPI.
- Không có ô nhập jump host (`ProxyJump`). `ssh` vẫn đọc `~/.ssh/config`, nên có thể khai `ProxyJump` ở đó cho host tương ứng. Tham số app truyền vào (`-p`, `user@host`, `-o ...`) ưu tiên hơn config.
