# Changelog

## Unreleased

- Added: `Profile.AllowLoopback` for permitting `127.0.0.0/8` and `::1` while `Net=false`.
- Added: Linux `Profile.LoopbackForwardPorts` for bridging explicit host `127.0.0.1:<port>` listeners into a `--unshare-net` sandbox.
