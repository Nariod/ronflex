# Ronflex
Rust offensive tool to suspend all known AV/EDRs processes, using the undocumented NtSuspendProcess API. Made with <3 for pentesters.

## WARNING
Ronflex suspends all known AV/EDRs and other security products processes. There is a high chance that the system will be unstable after Ronflex did its thing !

# Quick start

## Cross-compile from Linux

Install and configure Rust:
- https://www.rust-lang.org/tools/install
- `rustup target add x86_64-pc-windows-gnu`

Build the binary:
- `git clone https://github.com/Nariod/ronflex.git`
- `cd ronflex`
- `cargo build --release --target x86_64-pc-windows-gnu`

## Compile on Windows

Install and configure Rust:
- https://www.rust-lang.org/tools/install
- `rustup target add x86_64-pc-windows-msvc`

Build the binary:
- `git clone https://github.com/Nariod/ronflex.git`
- `cd ronflex`
- `cargo build --release`

## Usage
Run the binary with the highest privileges you can, and without argument to freeze all known security products:
- `ronflex.exe`

Alternatively, you can freeze a specific target process by passing the exact process name:
- `ronflex.exe msteams.exe`

## Credits
- [The Sliver project](https://github.com/BishopFox/sliver) for the list of known AV/EDRs processes
- Rust discord
- StackOverflow

## Legal disclaimer
Usage of anything presented in this repo to attack targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.
