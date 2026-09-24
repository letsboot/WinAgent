# WinAgent

An AI chat window for **Windows 95**. WinAgent talks to a model on [OpenRouter](https://openrouter.ai)
over TLS 1.2, straight from a 1995 PC. One exe, about 350 KB, no installer, no runtime DLLs.

## Use

1. Download `WINAGENT.EXE` from the [latest release](https://github.com/letsboot/WinAgent/releases/latest).
2. Copy it onto the Windows 95 PC (to the desktop, not a network share: Windows 95 won't start exes from SMB shares).
3. Start it, paste your OpenRouter API key ([openrouter.ai/keys](https://openrouter.ai/keys)), optionally pick a model, press OK.

The key is asked for at every start and kept only in memory. It is never written to disk.
Default model: `mistralai/mistral-nemo`.

## How it works

- Plain Win32 window, Winsock 1.1 (`WSOCK32.DLL`), no C runtime (Windows 95 has no `msvcrt.dll`).
  The exe imports only `KERNEL32`, `USER32`, `GDI32` and `WSOCK32`.
- TLS 1.2 by [BearSSL 0.6](https://www.bearssl.org/), compiled in without SSE/MMX (Windows 95 doesn't save SSE registers).
  Windows 95 has no crypto RNG, so the TLS seed is hashed from timer jitter, cursor and clock.
- HTTP/1.0 POST to `/api/v1/chat/completions`; the answer is found by a string search for `"content":"`.
- Server certificates are checked against the roots in [`src/ta.h`](src/ta.h) (GTS Root R1/R3/R4, ISRG Root X1/X2).
  To regenerate: `brssl ta GTS_Root_R1.pem GTS_Root_R3.pem GTS_Root_R4.pem ISRG_Root_X1.pem ISRG_Root_X2.pem > src/ta.h`.

## Build

On Linux (Ubuntu):

```sh
sudo apt-get install gcc-mingw-w64-i686
./build.sh
```

`build.sh` downloads BearSSL (sha256-pinned), builds `dist/WINAGENT.EXE` and checks it: PE subsystem 4.0,
only the four DLL imports above, no SSE/MMX instructions. Optional env: `WINAGENT_MODEL`, `WINAGENT_BUILD`,
`WINAGENT_FALLBACK_IP` (IP of openrouter.ai for PCs without DNS).

GitHub Actions builds every push; a tag `v*` publishes a release with the exe and its sha256.

## License

MIT, see [LICENSE](LICENSE). BearSSL is MIT, Copyright (c) 2016 Thomas Pornin.
