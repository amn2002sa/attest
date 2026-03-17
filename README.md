# 🛡️ attest - Secure AI Agent Auditing Made Simple

[![Download attest](https://img.shields.io/badge/Download-attest-brightgreen?style=for-the-badge)](https://github.com/amn2002sa/attest)

---

## 🔍 What is attest?

attest is a tool that helps keep AI agents safe and trustworthy. It uses strong hardware security (like TPM chips) and cryptography to create a secure history of what an AI agent does. This history is private and cannot be changed without detection. The software runs on Windows and is built using Go and Rust languages to ensure speed and safety.

Key points:
- Protects AI identity with hardware-based security.
- Creates an audit trail that proves what happened, without revealing sensitive data.
- Lets you undo actions safely, thanks to reversible execution technology.
- Uses modern, advanced security methods to keep data safe.

You don't need to be a programmer to use attest. This guide will help you set it up on your Windows PC.

---

## 💻 System Requirements

Before you install, check your system fits these minimum needs:

- Windows 10 or newer (64-bit recommended)
- Trusted Platform Module (TPM) chip version 2.0 enabled on your PC (usually found in BIOS settings)
- At least 4 GB of RAM
- 1 GB free disk space for installing files
- Internet connection to download the software
- Admin rights on your computer to complete setup

If your PC meets these requirements, you can proceed.

---

## 🚀 Getting Started: Download and Install

To get the software, you need to visit the official GitHub page and download the latest version.

[![Download attest](https://img.shields.io/badge/Visit%20Download%20Page-blue?style=for-the-badge)](https://github.com/amn2002sa/attest)

### Step 1: Visit the Download Page

Click the button above or go directly to https://github.com/amn2002sa/attest in your web browser.

- This page contains the latest releases of attest.
- Look for a file that ends with `.exe` for Windows. It might be named something like `attest-setup.exe` or similar.
- Click the file to start downloading it.

### Step 2: Run the Installer

- Once downloaded, find the `.exe` installer in your Downloads folder.
- Double-click it to start the installation.
- Follow the on-screen instructions. You usually can accept the defaults.
- When prompted, allow the installer to make changes to your system.

### Step 3: Finish Setup

- After the install finishes, there should be a new attest icon on your desktop or in your Start Menu.
- Double-click to open the application.

If you run into any prompts about security, confirm that you want to run the software.

---

## 🔧 How to Use attest

attest works by securely tracking information about AI agents on your PC. The software uses hardware features and cryptography to keep a private log of agent actions.

### Main Features

- **Hardware-sealed identity**: Uses your TPM chip to prove that only your device can run the AI agent.
- **Audit trail**: Records detailed logs of what the AI does, using zero-knowledge proofs. This means logs are private and trusted.
- **Undo actions**: If needed, you can reverse certain operations safely without losing security.
- **Cross-platform code**: Written in Go and Rust for reliability.

### Running Your First Audit

Inside the application:

1. Choose your AI agent from the list or add a new one by entering its name.
2. Start the audit process with the button labeled "Begin Audit."
3. attest will connect with your TPM chip and start tracking the agent's actions.
4. You will see a live status of events being logged securely.
5. You can pause or stop the audit at any time.

You do not need deep technical skills to run this. The interface guides you through the steps.

---

## ⚙️ Configuration Options

attest offers some simple settings you can adjust:

- **Agent list management**: Add or remove agents you want to monitor.
- **Log storage location**: Choose where to save audit files on your disk.
- **Undo limits**: Set how often or how far back you want the undo feature to work.
- **Privacy settings**: Control how detailed the audit trail reports are, balancing detail and privacy.

You will find these options in the "Settings" menu after opening attest.

---

## 🔑 Hardware Security Setup

To use attest properly, Windows must recognize the TPM (Trusted Platform Module) on your computer.

### Checking TPM Status

1. Press `Windows Key + R` to open Run.
2. Type `tpm.msc` and press Enter.
3. A window will open showing TPM status.
4. Ensure it says "The TPM is ready for use" and shows version 2.0.

If TPM is missing or disabled, check your computer’s BIOS settings or contact your PC manufacturer.

---

## 🛠 Troubleshooting Common Issues

- **attest won't start or install:** Make sure you are running the installer as an administrator.
- **No TPM found:** Verify TPM is enabled in BIOS or your PC includes the hardware.
- **Audit fails to run:** Check your internet connection and that Windows is up to date.
- **Undo feature not working:** Ensure you have enough disk space and the feature is enabled under Settings.

If you need support, check the Issues section of the GitHub page for help.

---

## 📁 Where to Find Logs and Data

attest saves audit logs in a folder on your Windows PC. By default, logs are stored here:

`C:\Users\<YourUserName>\Documents\attest_logs`

You can change this location via the Settings menu inside the app.

Logs are safe and cannot be edited or deleted without detection.

---

## 🔒 Security and Privacy

attest uses your TPM chip and strong cryptographic methods to keep your AI work private and secure.

- Your identity is sealed to your hardware.
- Audit trails use zero-knowledge proofs, which confirm actions without revealing sensitive details.
- All logs are protected against tampering.
- Reversible actions do not expose sensitive data and keep your system in a safe state.

This design helps maintain trust and compliance in AI operations.

---

## 📚 More Information

For more details, check the repository on GitHub:

https://github.com/amn2002sa/attest

Here, you can find documentation, source code, and updates.

---

[![Download attest](https://img.shields.io/badge/Visit%20Download%20Page-blue?style=for-the-badge)](https://github.com/amn2002sa/attest)