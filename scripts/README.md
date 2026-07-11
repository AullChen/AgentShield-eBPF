# scripts

Developer, environment-check, and demo helper scripts live here.

Current files:

- `test-audit.sh`: triggers one file-open action and one process execution for
  the Linux audit loop.

The script only triggers events; it does not build or load BPF. The current
audit loop is host-wide and should only be run in an isolated VM/test host.
