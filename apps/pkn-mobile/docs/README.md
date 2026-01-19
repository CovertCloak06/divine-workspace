# PKN Mobile Documentation

Quick reference for PKN Mobile (Android/Termux).

## Quick Links

| Need | Doc |
|------|-----|
| **Deploy PKN Mobile** | [Deployment Guide](./DEPLOYMENT_MOBILE.md) |
| **Fix an issue** | [Troubleshooting](./TROUBLESHOOTING_MOBILE.md) |
| **AI assistant help** | [CLAUDE.md](../CLAUDE.md) |
| **Agent configuration** | [Agents Reference](../../../docs/AGENTS.md) |
| **OSINT tools** | [Shadow OSINT](../../../docs/SHADOW_OSINT.md) |
| **All documentation** | [Documentation Index](../../../docs/INDEX.md) |

## Quick Start

```bash
# In Termux
cd ~/pkn
python backend/server.py &
# Open: http://localhost:8010
```

## Mobile vs Desktop

| Feature | Mobile | Desktop |
|---------|--------|---------|
| Models | 7B (lighter) | 14B (full) |
| Storage | ~20GB | ~40GB |
| Response | 7-15s | 15-30s |
| UI | Mobile responsive | Full desktop |

See [Agents Reference](../../../docs/AGENTS.md) for complete comparison.

## Key Files

| File | Purpose |
|------|---------|
| `backend/server.py` | Main server |
| `backend/agents/manager.py` | Agent orchestration |
| `backend/config/model_config.py` | Model configuration |
| `css/mobile.css` | Mobile styles |
| `CLAUDE.md` | AI assistant instructions |

## Documentation Index

- [DEPLOYMENT_MOBILE.md](./DEPLOYMENT_MOBILE.md) - Full setup guide
- [TROUBLESHOOTING_MOBILE.md](./TROUBLESHOOTING_MOBILE.md) - Fix issues
- [../CLAUDE.md](../CLAUDE.md) - Configuration reference

## Workspace Docs

- [Documentation Hub](../../../docs/INDEX.md)
- [Agents Reference](../../../docs/AGENTS.md)
- [Tools Reference](../../../docs/TOOLS.md)
- [Shadow OSINT](../../../docs/SHADOW_OSINT.md)
- [Main Deployment](../../../docs/DEPLOYMENT.md)
- [Main Troubleshooting](../../../docs/TROUBLESHOOTING.md)
