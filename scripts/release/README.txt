Parano1d Native Release
=======================

Each release contains two independent product lines.

GUI Wallet packages (ordinary users):

  Linux:   parano1d-gui-vVERSION-linux-ARCH.deb
  Windows: parano1d-gui-vVERSION-windows-x86_64-setup.exe
  macOS:   parano1d-gui-vVERSION-macos-ARCH.dmg

The GUI package exposes only the Parano1d wallet application. Its full node
is bundled as a private application component and is supervised by the wallet.
The user does not need to start a daemon or use a terminal.

Core archives (node operators and miners):

  parano1d        full node and built-in miner
  parano1d-cli    wallet and node command-line client
  parano1d-miner  external proof-of-work miner
  LICENSE/NOTICE  Apache-2.0 distribution terms and project notices

Scheduled v2
------------

Mainnet changes rules automatically at block H210537. Before that height the
existing v1/v1.1 rules apply; from it the target interval is 30 seconds and
contract spending becomes available. The fork is selected by height, not by
the computer's clock.

The GUI Contracts tab provides six templates, a custom integer-program editor,
funding, reviewed calls, public terms and receipt import/export. Keep backups
of watched public terms and receipts alongside your wallet backup.

F7 has Create, My contracts and Open file. In My contracts, Operations & receipts
includes locally retained calls from both participants. Save receipt exports a
single operation; Share contract sends terms with one matching receipt when
available. Open either through F7 -> Open file. Import merges by transaction ID,
preserving your existing records and local name. F4 Receipts is for ordinary
payments. A file does not contain the sender's entire journal.

Call fee limit (default 1 NOID) is a ceiling for future calls. Saving unfunded
terms is free. Funding and calls show their actual network fee before signing.
If you missed calls that peers have already pruned, obtain updated terms or a
receipt from a participant, then check the current balances. Back up the GUI's
wallet.contracts.json and contract-activity/ together with the node's complete
objects/ directory, including objects/terminals/.

Node operators can inspect availability and class limits with:

  parano1d-cli contract protocol

Default Small blocks have 63 pages, 504 inputs and up to 63 contract calls.
Large blocks have 206 pages with the same input and call limits. Calls use
the page budget shared with payments. A server operator can permit Large
production by adding --v2-large-blocks to the node's internal or external
mining invocation. The flag is optional; every node verifies both classes.
There is no Large-class control in the GUI.

Hardware check
--------------

Before creating node or wallet data, run:

  parano1d --check-hardware

Production requires SSE4.1 and PCLMULQDQ on x86-64, or NEON and PMULL on
ARM64. The executable selects wider AVX2+VPCLMULQDQ or AVX-512 kernels
automatically. Unsupported hardware exits with a readable diagnostic; the
scalar reference backend is not used for production.

Verify the download
-------------------

Download SHA256SUMS from the same release as this archive:

  https://git.parano1d.org/ignotusnemo/parano1d/releases

Before extracting or running anything, compute the archive's SHA-256 digest
and compare it with the matching line in SHA256SUMS.

Linux:

  sha256sum <downloaded-archive>

macOS:

  shasum -a 256 <downloaded-archive>

Windows PowerShell:

  Get-FileHash <downloaded-archive> -Algorithm SHA256

Never run an archive whose digest does not match.

GUI Wallet — Linux
------------------

Open the downloaded .deb in the system Software application, or install it
from a terminal:

  sudo apt install ./parano1d-gui-vVERSION-linux-ARCH.deb

Launch Parano1d from the desktop application menu. Removing the package does
not remove wallet data from the user's home directory.

GUI Wallet — Windows
--------------------

Run the downloaded setup.exe and launch Parano1d from the Start menu. The
installer is per-user and does not require administrator privileges by
default.

Until the project uses an Authenticode certificate, Microsoft Defender
SmartScreen may display a warning. After verifying SHA256SUMS, select
"More info" and then "Run anyway".

GUI Wallet — macOS
------------------

Open the downloaded DMG and drag Parano1d.app to Applications. Launch it from
Applications like any other app.

Until the project uses an Apple Developer ID certificate, macOS may block the
first launch. After verifying SHA256SUMS, Control-click Parano1d, choose Open,
and confirm. If necessary, use Privacy & Security -> Open Anyway.

Core archive — Linux
--------------------

Open a terminal in the extracted directory:

  ./parano1d --help
  ./parano1d-cli --help
  ./parano1d-miner --help

Core archive — macOS
--------------------

If Gatekeeper blocks a verified download, remove only the quarantine
attributes from the three extracted binaries:

  xattr -d com.apple.quarantine ./parano1d
  xattr -d com.apple.quarantine ./parano1d-cli
  xattr -d com.apple.quarantine ./parano1d-miner

If xattr reports that an attribute does not exist, no action is required.
Then run:

  ./parano1d --help

Core archive — Windows
----------------------

PowerShell can unblock all three verified extracted executables at once:

  Get-ChildItem .\*.exe | Unblock-File

Then run:

  .\parano1d.exe --help

Node data
---------

The first node start creates its configuration and persistent data under:

  Linux/macOS:  ~/.parano1d/
  Windows:      %USERPROFILE%\.parano1d\

The wallet key is stored in data/wallet.key and is not password-encrypted.
Back it up and protect it before receiving funds.

Documentation: https://docs.parano1d.org/
Source:        https://git.parano1d.org/ignotusnemo/parano1d
