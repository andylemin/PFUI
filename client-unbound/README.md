# PFUI_Unbound (client)

The PFUI client for [Unbound](https://nlnetlabs.nl/projects/unbound/about/).
Installed on the resolvers, it forwards successfully resolved IPs and their TTLs
to every PFUI server.

`pfui_unbound.py` is an Unbound **pythonmod plugin**, not a script. Unbound
executes it in the embedded interpreter's `__main__` namespace, injects
`log_info`, `log_err` and the `MODULE_*` constants, and calls `init`,
`init_standard`, `deinit`, `inform_super`, `operate` and
`inplace_cache_callback` itself. Nothing in PFUI calls those, which is why
`tests/test_unbound_module.py` pins their signatures: a rename here would surface
only on a running resolver.

| Path | What it is |
|------|------------|
| `pfui_unbound.py` | The plugin |
| `pfui_unbound.yml` | PFUI client configuration (firewall list, transport, timeouts) |
| `examples/pfui_unbound.conf` | Example Unbound config with the module enabled |
| `rc.d/pfui_unbound` | OpenBSD rc.d script for the Unbound build with pythonmod |
| `tools/` | Root hints and DNS blocklist updaters, run from cron |
| `docs.pythonmod/` | Vendored Unbound pythonmod documentation, from NLnet Labs |

Install with `../install-client-unbound.sh` from the repository root. The wire
format it speaks is specified in [../protocol/PROTOCOL.md](../protocol/PROTOCOL.md);
the installer places `pfui_wire.py` beside the plugin.

Adding a client for another resolver means a new `client-<resolver>/` directory
that speaks the same protocol. Nothing in this directory is shared.
