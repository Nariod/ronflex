# Ronflex
Rust offensive tool to suspend all known AV/EDRs processes using syscalls and the undocumented NtSuspendProcess API. Made with <3 for pentesters.

## WARNING
Ronflex tries to suspend all known AV/EDRs and other security products processes. There is a high chance that the system will be unstable after Ronflex did its thing ! Use at your own risks.

## Known limitations
At the moment, Ronflex is not able to suspend processes protected Anti-Malware Protected Process (AM-PPL). WIP..

## Todo
- [x] Loop over known processes to suspend them
- [x] Support for a specific process target
- [x] Move the NtSuspendProcess and NtClose API calls to syscalls 
- [x] Move the remaining API calls to syscalls
- [ ] Embbed a method to bypass AM-PPL. [PPLmedic](https://github.com/itm4n/PPLmedic) maybe ?

# Quick start

## Binary
If you're in a  hurry, you will find a ready to deploy x64 binary for Windows. However, you should take time to compile it yourself.
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
Run the binary with the highest privileges you can and without argument to freeze all known security products:
- `ronflex.exe`

Alternatively, you can freeze a specific target process by passing the exact process name:
- `ronflex.exe notepad.exe`

![Notepad put to sleep](img/ronflex_notepad.png)

## Credits
- janoglezcampos for his [rust_syscalls](https://github.com/janoglezcampos/rust_syscalls) project
- [The Sliver project](https://github.com/BishopFox/sliver) for the list of known AV/EDRs processes
- Rust discord
- StackOverflow

## Legal disclaimer
Usage of anything presented in this repo to attack targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.
