# `profile.rules` format, version 2

`agentfence synth` writes two files next to each other:

* `.agentfence/profile.toml`: the human-readable, annotated profile (roles, warnings, blocked secrets, informational network endpoints). This is the source of truth that `agentfence run` and `report` read.
* `.agentfence/profile.rules`: a flat compiled form of the *enforceable* subset, for launchers that do not want a TOML parser. `launcher/agentfence-exec.c` is one such launcher, written in C. Both files are generated in the same `synth` run and always agree.

Version history: version 1 had no name for `connect_unix` and carried no hardening or network-enforcement flags. Version 2 adds the `resolve_unix` right and `option` lines. `synth` writes version 2; both parsers (`src/rules.rs`, `launcher/rules.c`) accept 1 and 2. Version-2-only syntax in a version 1 file is rejected.

## Grammar

The file is UTF-8 text, LF line endings.

```
file    = header *( line )
header  = ( "agentfence-rules 1" / "agentfence-rules 2" ) LF
line    = comment / rule / empty
comment = "#" *( any char except LF ) LF
empty   = LF
rule    = fsrule / netrule / optrule
fsrule  = "fs" TAB path TAB rights LF
netrule = "net" TAB ( "connect" / "bind" ) TAB port LF
optrule = "option" TAB ( "net_enforce" / "scope_signal" / "scope_abstract_unix" ) LF   ; version 2 only
rights  = right *( "," right )
port    = 1*DIGIT, value 0..65535 (no sign)
```

* The first line is exactly `agentfence-rules 1` or `agentfence-rules 2`. A reader that does not recognise the version must refuse the file.
* A reader splits the file at LF and strips one CR before the LF if present; the last line may lack its LF. The text must be valid UTF-8. Anything else that does not match the grammar (a relative path, an unknown right, a wrong field count, whitespace-only lines, a signed port) is an error reported with its line number; there is no partial acceptance.
* Fields are separated by a single TAB. `path` is everything between the first and second TAB, byte for byte, with no quoting or escaping. Because of that, `synth` fails with an error if a rule path contains a TAB, LF or CR; such a path can never appear in the file.
* `path` is absolute, normalized, and symlink-free (resolved at synth time). It existed when the profile was generated; a launcher should skip rules whose path no longer exists (Landlock cannot attach a rule to a missing path) and may warn.
* Rule order carries no meaning. `synth` emits filesystem rules sorted by path, then `connect` ports ascending, then `bind` ports ascending.
* Lines starting with `#` are comments; empty lines are ignored.

## Rights

Landlock `LANDLOCK_ACCESS_FS_*` names, lowercase, without the prefix:

`execute`, `write_file`, `read_file`, `read_dir`, `remove_dir`, `remove_file`, `make_char`, `make_dir`, `make_reg`, `make_sock`, `make_fifo`, `make_block`, `make_sym`, `refer`, `truncate`, `ioctl_dev`, `resolve_unix` (version 2 only; Landlock ABI 9, connecting to a pathname unix socket).

Within a rule the rights are written in the order above, without duplicates.

What `synth` actually emits:

| profile access | rights in `profile.rules` |
|----------------|---------------------------|
| `read_file`    | `read_file` |
| `read_dir`     | `read_dir` |
| `exec`         | `execute` |
| `connect_unix` | `resolve_unix` (version 2) |
| `write`        | `write_file,remove_dir,remove_file,make_dir,make_reg,make_sock,make_fifo,make_sym,refer,truncate` (canonical order) |

* If the path is not a directory at synth time, only the file-valid rights are emitted (`execute`, `write_file`, `read_file`, `truncate`, `ioctl_dev`, `resolve_unix`), because Landlock rejects directory-only rights on a file rule.
* `make_char`, `make_block` and `ioctl_dev` are valid names but are never emitted. A launcher should *handle* (deny by default) the Landlock rights it supports, including these, so that anything not granted is denied; it should not handle `ioctl_dev` if it wants the same behaviour as `agentfence run`, which leaves device ioctls unrestricted.
* `connect_unix` rules (Landlock ABI 9 `resolve_unix`) are written as `resolve_unix`. A launcher on a kernel older than ABI 9 cannot enforce the right; `agentfence run` and `agentfence-exec` both handle it (deny unix socket lookups unless granted) when the kernel supports it.
* A rule whose rights collapse to nothing for its path type is omitted.

## Network rules

`net connect <port>` allows TCP `connect()` to that port (`LANDLOCK_ACCESS_NET_CONNECT_TCP`); `net bind <port>` allows TCP `bind()` (`LANDLOCK_ACCESS_NET_BIND_TCP`; port 0 means "ephemeral port"). Landlock filters by port only, never by address.

Network rules are emitted only when the profile has `network.enforce = true`. If there are no `net` lines **and** the launcher handles the TCP rights, all TCP connects/binds are denied; the file does not otherwise say whether to handle them. A launcher that wants to match `agentfence run` should handle both TCP rights exactly when `profile.toml` has `network.enforce = true` (a future format version may add an explicit directive).

## Options (version 2)

`option` lines carry what used to live only in `profile.toml`, so a launcher can enforce the same policy as `agentfence run`:

* `option net_enforce`: handle (deny unless granted) TCP connect and bind. Same meaning as `network.enforce = true`. Without it the file's `net` lines are moot.
* `option scope_signal`: deny sending signals to processes outside the sandbox (ABI 6).
* `option scope_abstract_unix`: deny connecting to abstract unix sockets created outside the sandbox (ABI 6).

`synth` writes each option exactly when the profile enables it. Duplicates are harmless. A version 1 file has no options; the C launcher then treats it as: TCP handled iff the file has `net` lines, both scopes on (the `hardening` defaults).

## Example

```
agentfence-rules 2
# generated by `agentfence synth`; edit profile.toml and re-run synth instead
fs	/dev/null	write_file,truncate
fs	/home/me/proj/src	write_file,read_file,read_dir,remove_dir,remove_file,make_dir,make_reg,make_sock,make_fifo,make_sym,refer,truncate
fs	/usr/bin/git	execute,read_file
net	connect	443
```

with, after the comment, the lines `option	net_enforce`, `option	scope_signal` and `option	scope_abstract_unix` (omitted from the sample above to keep it short).

(Fields are TAB separated in the real file.)

## Reference implementation

`src/rules.rs` contains both the writer (`compile`) and a strict reference parser (`parse`) with a round-trip unit test. Treat the parser as the executable form of this document. `launcher/rules.c` is an independent C implementation of the same grammar; `tests/launcher.rs` feeds both the same inputs and requires identical accept/reject decisions.
