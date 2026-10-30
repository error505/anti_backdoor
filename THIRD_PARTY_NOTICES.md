# Third-party notices

Flockion Backdoor Watch is MIT licensed (see [LICENSE](LICENSE)). It depends on the open-source
components below, each under its own license. Run `pip-licenses` (backend) or
`npx license-checker` (frontend) for the complete, current list.

| Component | Use | License |
| --- | --- | --- |
| FastAPI, Starlette, Uvicorn | Backend web server | MIT / BSD-3-Clause |
| psutil | Process and socket data | BSD-3-Clause |
| Pydantic | Data models | MIT |
| Scapy | Optional packet inspection | GPL-2.0 (used as an optional, separately installed library) |
| anthropic, openai (Python SDKs) | Optional AI analysis | MIT / Apache-2.0 |
| websockets | Flockion agent connection | BSD-3-Clause |
| React, React DOM | Frontend | MIT |
| TanStack Query | Frontend data fetching | MIT |
| react-markdown | Renders AI output | MIT |
| Vite | Frontend build | MIT |
| Orbitron, Rajdhani, Share Tech Mono (via `@fontsource/*`) | UI fonts, bundled locally | SIL Open Font License 1.1 |

**Scapy** is GPL-2.0. This project only imports it when you start packet capture, and does not
copy its code. If you redistribute a bundle that includes Scapy, follow the GPL for that part,
or remove `scapy` from `backend/requirements.txt` (packet inspection then stays disabled).

**Fonts** are licensed under the SIL OFL 1.1, which allows bundling and redistribution provided
the font license is kept with them. The license texts ship inside `frontend/node_modules/@fontsource/*`
and in the built `frontend/dist` assets' source packages.

## Detection indicators

`backend/backdoor_watch/analysis/ioc_rules.json` is assembled from public threat reporting on the
"Contagious Interview" campaign (including Microsoft Security Blog, 2026-03-11, and Malpedia
entries for BeaverTail and InvisibleFerret). Only indicator facts (names, ports, paths, patterns)
are used, not copied text.

## Trademarks

"Flockion" is the name of a separate product and company. "Claude" and "Anthropic" belong to
Anthropic PBC; "OpenAI" and "GPT" belong to OpenAI. Those names appear only to say which
services this tool can optionally call.
