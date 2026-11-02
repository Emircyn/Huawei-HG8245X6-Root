# Huawei CLI agent guide

Read `CLI.md` for command examples. Run `huawei help` for the implemented command/options inventory. This repository wraps the upstream v2.0.1 C# Core; do not automate its desktop GUI.

## Executable and invocation

- Local executable: `/home/emircyn/.local/bin/huawei` (symlink to `src/publish/huawei`). Portable repository-relative entry: `src/publish/huawei`.
- Syntax: command words first, then `--option value`. Options before command words and `--key=value` are unsupported. `--show-secrets` is the only valueless flag. Boolean values are `true`/`false`.
- Each invocation is a separate process/session. Pass `--host` and `--user` consistently; defaults are `192.168.1.1` and `admin`. Do not run concurrent operations on the same router: firmware may allow only one web session.
- GUI default password is used when no password file or nonblank environment value is supplied. Priority: password file > environment > GUI default. An explicitly empty password file is an error.
- Authentication: existing `HUAWEI_PASSWORD` environment variable or `--password-file`. Never paste credentials into command arguments or logs. Secret-changing commands accept the NAME of an environment variable, e.g. `--psk-env WIFI_KEY`.
- stdout is one JSON object; stderr contains progress logs. Capture both separately and inspect exit status even when JSON parses successfully.

## Performing a user's request

1. Establish the intended device and existing credentials from session context. When the user requests default behavior, use the GUI defaults without asking for credentials again.
2. Read current state using the relevant `get` command. Use device-provided band instance/domain identifiers.
3. Invoke the smallest command implementing the authorized change. Writes execute immediately without a prompt. The CLI's availability does not authorize unrelated changes; do not repeatedly request permission for an already authorized operation.
4. Check JSON `state`, warnings, and exit status. Read back changed settings. Report exactly what was observed and any unresolved state.

Use typed commands for Wi-Fi, DNS, firewall, ALG and TR-069. For firmware-specific settings, inspect device pages before using `http post`/`wan set`; do not invent endpoint names or parameter schemas. Form JSON values must be strings; ALG JSON values must be booleans. Generic HTTP POST adds the session token automatically. Quote query strings in shell commands.

`config get/edit/decrypt` operate on local files. XML edit selects exactly one element and an existing attribute; it does not upload. Config restore is a separate operation. Newly created CLI backup files refuse overwrite and use 0600 permissions on Linux. Restore makes a safety backup before uploading; profile restore can partially apply.

## Result interpretation

| Result | Interpretation |
|---|---|
| `state=read`, exit 0 | Read completed; this is not proof of any desired device configuration. |
| `state=verified`, exit 0 | Command-specific readback passed; it is not a whole-device health test. |
| `state=submitted`, exit 5 | Write was attempted/submitted, actual application is unconfirmed. `ok=true` does NOT establish success. |
| `state=partial`, exit 5 | Some data is unavailable; missing fields must not be interpreted as disabled settings. |
| exit 2 / 3 / 4 | Input validation / authentication / runtime or network failure. |
| exit 130 | Cancellation or timeout; writes might already have taken effect. |

Do not blindly retry writes after timeout, disconnect or exit 5. Inspect state first. Password/config changes may reboot or disconnect the device. Verify new authentication after it returns.

Structured passwords are masked unless `--show-secrets` is present. Raw HTTP/SSH output and backup files can still contain secrets. Do not include these in user-facing responses unless needed for the request.

## Capability boundaries

- `credentials get` reads through an authenticated configuration download. `credentials recover` is a different, mutating USB/SMB/SFTP recovery workflow requiring Python `paramiko` and `pysmb`. It changes services and creates accounts; full restoration of previous service settings is not guaranteed.
- `access password --user sUser --method web` needs the current sUser password. `--method race` requires physical power timing; do not describe it as fully autonomous. No automatic fallback from web to race.
- SSH requires a trusted SHA256 host-key fingerprint and an exec-capable server. Some WAP shells only support interactive access; do not claim exec support before testing.
- Firmware-specific HTML/JS parsing and write semantics require real-device validation. Loopback tests do not establish hardware compatibility. Release binary identity was checked with REA, not full source/binary equivalence; see `../ANALYSIS.md`.

## Development and checks

Core lives in `src/Core`; CLI entry point is `src/Cli/Program.cs`; project is `src/HekzOntRace.Cli.csproj`. Reuse Core and preserve GPL v2 licensing. Changes to shared Core can affect Windows/Linux GUIs too.

Local SDK: `/home/emircyn/hg8245x6-analysis/.dotnet/dotnet`.

```sh
dotnet publish src/HekzOntRace.Cli.csproj -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true -o src/publish
src/publish/huawei self-test
python3 -m unittest discover -s tests -v
git diff --check
```

Tests bind only loopback and use fake credentials. Do not turn automated tests into real router mutations. Update CLI.md and the help inventory when command behavior changes. State separately what passed in mocks and what remains untested on hardware.
