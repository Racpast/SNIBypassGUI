# Vendored WinDivert 2.2.2

This directory holds the **source-level** vendored drop of WinDivert 2.2.2
(<https://github.com/basil00/Divert>, <https://reqrypt.org/windivert.html>):

- `include/windivert.h` — the stock upstream header, used unmodified. At build time
  `src/dns/interceptor.cpp` defines `WINDIVERTEXPORT` to empty **before** including it, so
  the header's `dllimport` prototypes are neutralized and we reuse only its
  structs/enums/constants. Every WinDivert entry point is resolved at runtime via
  `LoadLibrary`/`GetProcAddress`.
- `LICENSE`, `README` — upstream license and readme, shipped for compliance.

## Where are the binaries?

The runtime binaries (`WinDivert.dll`, `WinDivert64.sys`) are **not** kept here.
They live under `resources/payload/` and ship next to `SNIBypassGUI.exe` in the
Release ZIP — they are **not** embedded in the exe. Like the rest of the payload
they are delivered/updated through the signed manifest. The DLL is loaded by full
path from beside the exe; the DLL then loads its own `WinDivert64.sys` from that
same directory. There is intentionally a single copy.

## License / compliance

WinDivert is dual-licensed under **LGPLv3** or **GPLv2** (your choice); see
`LICENSE`. This project links WinDivert purely by **runtime dynamic loading**,
and the DLL ships as a plain, user-replaceable file next to the
executable. That satisfies the LGPL requirement that users be able to replace
the library, so the application may adopt any license (including a proprietary
one) provided this `LICENSE`/`README` accompany the distribution.

The import library (`WinDivert.lib`) is intentionally absent: dynamic loading
never needs it.
