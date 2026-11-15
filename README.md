# BASH-FILE-INTEGRITY-CHECK
A pair of menu-driven scripts that detect unauthorized changes and file  tampering, and give an at-a-glance encryption/privacy status of your files.
The same four-option menu on both platforms:
1.	Create a baseline SHA-256 manifest of a folder
2.	Verify files against that manifest (changed / missing / new files)
3.	Check encryption status (Windows: NTFS/EFS per-file encryption;

Linux: encrypted-filesystem detection + world-readable permission audit)
4.	Hash a single file and compare it with a published checksum
No dependencies beyond the shell: PowerShell on Windows, Bash + coreutils

(sha256sum, stat, find, findmnt) on Linux.
How it works
·	Baseline (option 1): every file under the chosen folder is hashed with

SHA-256; the relative path, hash, size, and timestamp are written to
IntegrityManifest.csv next to the script.
·	Verify (option 2): files are re-hashed and compared against the

manifest. The report lists MODIFIED, MISSING, and NEW files, then prints

PASS or FAIL.
Quick start — Windows
Right click script, choooe Run with PowerShell
.\Check-FileIntegrity.ps1
# If script execution is blocked:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Check-FileIntegrity.ps1

Requires Windows PowerShell 3.0 or newer (preinstalled on every Windows since

8 / Server 2012) or PowerShell 7+. Older PowerShell 2.0 hosts are not

supported — [PSCustomObject] and Get-ChildItem -File both require 3.0+,

despite what older comments in the script header may suggest.
Quick start — Linux (Ubuntu/Debian)
chmod +x check-file-integrity.sh
./check-file-integrity.sh

Requires Bash 4.0+ and GNU coreutils — both stock on Ubuntu/Debian.

Run it from a writable folder (the manifest is saved to the current directory).
Menu
Option	Action
1	Create baseline manifest (IntegrityManifest.csv)
2	Verify a folder against the manifest
3	Encryption / privacy status (EFS on Windows; filesystem + permissions on Linux)
4	Compute/compare a single file hash
Q	Quit

Known limitations (v1.0) — read before use
·	Manifests are per-platform. Create the baseline and verify on the same

OS. The Windows CSV uses quoted fields, uppercase hashes, backslash path

separators, and a UTF-8 BOM; the Linux verifier expects unquoted,

lowercase, forward-slash rows — feeding it a Windows manifest reports every

entry as missing (and vice versa, the Windows verifier's new-file detection

assumes backslash paths). A unified, portable manifest format is on the

roadmap.
·	Hidden files are handled differently: the Windows version skips hidden

files (Get-ChildItem without -Force); the Linux version includes them.
·	Filenames containing commas corrupt rows in the Linux manifest (the

Bash writer does not do CSV quoting).
·	Linux: enter the folder path without a trailing slash — a trailing

slash makes the manifest store absolute paths instead of relative ones.
·	Encryption checks differ by design: Windows reads the NTFS/EFS

per-file encryption attribute; Linux detects encrypted filesystems

(eCryptfs/gocryptfs) and flags world-readable files. LUKS full-disk

encryption is invisible to both.
·	A PASS result means the files match the recorded hashes — it is not

proof that a system is free of malware. A compromised OS can lie to any

hashing tool, including this one.
Roadmap
·	Unified cross-platform manifest format (Windows baseline ↔ Linux verify

and vice versa)
·	CSV quoting in the Bash manifest writer (filenames with commas)
·	Include hidden files in the Windows baseline (-Force)
·	Normalize trailing slashes in the Linux path input
License
Released under the MIT License — see LIC
