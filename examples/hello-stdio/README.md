# hello-stdio (demo notes upstream)

Small **stdio** MCP server for the local demo: namespace `notes`, tools `list` and
`read` (published by Keystone-MCP as `notes_list` and `notes_read`). It only reads
files under `notes/` next to this script — no paths or `..` in names.

**Why:** shows RBAC and proxying for a child process Keystone-MCP starts (not HTTP).

**Run alone** (from this directory):

```bash
uv run python server.py
```

In [MCP Inspector](https://github.com/modelcontextprotocol/inspector), connect with
transport **stdio**, command `python` (or `uv run python`), args `server.py`, cwd
this folder. You should see `list` and `read`; `list` returns `alpha.txt` and
`beta.txt`.

**In the demo stack**, Keystone mounts this tree at `/opt/hello-stdio` and runs
`python /opt/hello-stdio/server.py` — see `examples/demo/upstreams.yaml` and
`docker-compose.demo.yml`.
