# 🔐 Password Manager

A secure, offline-first, cross-platform password manager built with [Tauri](https://tauri.app/), [Rust](https://www.rust-lang.org/), and [SQLCipher](https://www.zetetic.net/sqlcipher/). This desktop application enables users to safely store and manage credentials using encryption.

![Tauri](https://img.shields.io/badge/tauri-v2-blue.svg)
![Rust](https://img.shields.io/badge/rust-2021-orange)
![License](https://img.shields.io/github/license/tasarma/password-manager)
![Build](https://img.shields.io/github/actions/workflow/status/tasarma/password-manager/ci.yml?branch=main)

---

## 🚀 Features

- 🧱 **Fully Offline**: All data is stored locally. No cloud sync.
- 🔐 **AES-256-GCM Encryption**: Passwords are encrypted with a secure key derived using Argon2.
- 🧂 **Per-device Salt**: Unique salt stored securely for each installation.
- 🧠 **Master Password Login**: Enforces secure authentication via Argon2-derived encryption key.
- 🗃️ **Encrypted or Plain DB Option**: Use SQLCipher for full database encryption, or just encrypt entries.
- 📝 **Password Metadata**: Store title, username, URL, notes, and timestamps.
- 📥 **Export-Ready Codebase**: Build native `.msi`, `.dmg`, `.deb`, and `.AppImage` installers.

---

## 🧰 Tech Stack

| Layer      | Technology                  |
|------------|-----------------------------|
| Backend    | Rust, SQLx, SQLCipher       |
| Frontend   | HTML, CSS, TypeScript       |
| Encryption | Argon2, AES-GCM             |
| Framework  | Tauri (v2)                  |
| Async      | Tokio                       |


---

## 🛡️ Security

- **Encryption**: All password entries are encrypted using AES-256-GCM before storing in SQLite.
- **Key Derivation**: Argon2id is used with high iteration count and memory cost to protect against brute-force attacks.
- **Salt Storage**: Each device generates a random salt file stored outside the DB to enhance KDF uniqueness.
- **Database Locking**: Optionally encrypt the full database using SQLCipher.

---

## 📦 Installation

### 🖥 Windows / macOS / Linux

Visit the [Releases](https://github.com/tasarma/password-manager/releases) page to download the latest installer:

- Windows: `.msi`
- macOS: `.dmg`
- Linux: `.deb` or `.AppImage`

> No internet access is required after installation.

### Installation Instructions

#### Windows

1. Download the `.msi` installer.
2. Open the Command Prompt (`cmd`).
3. Navigate to the directory where the installer is located.
4. Run the installer by typing its name, for example:
```password-manager_0.1.0_x64-setup.exe```
5. Follow the on-screen instructions to complete the installation.

---

#### macOS

1. Download the `.dmg` file.
2. Double-click it to open.
3. Drag the application into your **Applications** folder.
4. Launch it from the **Applications** folder.

---

#### Linux

#### Using `.AppImage`

1. Download the `.AppImage` file.
2. Make it executable:
```bash
chmod +x password-manager_0.1.0_amd64.AppImage
```
3. Run it:
```bash
./password-manager_0.1.0_amd64.AppImage
```
   
---

## 🧑‍💻 Development

### Clone & Build

```bash
git clone https://github.com/tasarma/password-manager.git
cd password-manager
pnpm install
pnpm run tauri dev
```

---

## 🧑‍💻 Contribute

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/improvement`)
3. Make your changes
4. Commit your changes (`git commit -am 'Add new feature'`)
5. Push to the branch (`git push origin feature/improvement`)
6. Create a Pull Request

Please ensure your PR description clearly describes the changes and their benefits.
