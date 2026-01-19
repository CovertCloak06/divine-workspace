# PKN Shared Package - Migration Guide

## Purpose

This package consolidates common backend code shared between:
- `apps/pkn/` (PKN Desktop)
- `apps/pkn-mobile/` (PKN Mobile)

## Files to Migrate

### Phase 1: Tool Modules (Identical)
| File | Source | Notes |
|------|--------|-------|
| `code_tools.py` | apps/pkn/backend/tools/ | Identical in both |
| `file_tools.py` | apps/pkn/backend/tools/ | Identical in both |
| `system_tools.py` | apps/pkn/backend/tools/ | Identical in both |
| `web_tools.py` | apps/pkn/backend/tools/ | Identical in both |
| `memory_tools.py` | apps/pkn/backend/tools/ | Identical in both |
| `osint_tools.py` | apps/pkn/backend/tools/ | Identical in both |
| `rag_tools.py` | apps/pkn/backend/tools/ | Identical in both |
| `planning_tools.py` | apps/pkn/backend/tools/ | Identical in both |
| `delegation_tools.py` | apps/pkn/backend/tools/ | Identical in both |
| `chain_tools.py` | apps/pkn/backend/tools/ | Identical in both |
| `sandbox_tools.py` | apps/pkn/backend/tools/ | Identical in both |
| `evaluation_tools.py` | apps/pkn/backend/tools/ | Identical in both |
| `scratchpad_tools.py` | apps/pkn/backend/tools/ | Identical in both |
| `workflow_tools.py` | apps/pkn/backend/tools/ | Identical in both |
| `git_tools.py` | apps/pkn/backend/tools/ | Identical in both |
| `project_tools.py` | apps/pkn/backend/tools/ | Identical in both |
| `pentest_tools.py` | apps/pkn/backend/tools/ | Identical in both |
| `recon_tools.py` | apps/pkn/backend/tools/ | Identical in both |
| `privesc_tools.py` | apps/pkn/backend/tools/ | Identical in both |
| `network_tools.py` | apps/pkn/backend/tools/ | Identical in both |
| `crypto_tools.py` | apps/pkn/backend/tools/ | Identical in both |

### Phase 2: Agent Definitions (Mostly Identical)
| File | Source | Notes |
|------|--------|-------|
| `types.py` | apps/pkn/backend/agents/ | AgentType enum, TaskComplexity |
| `classifier.py` | apps/pkn/backend/agents/ | Task classification logic |

### Phase 3: Routes (Identical)
All route files in `backend/routes/` are identical between apps:
- health.py, phonescan.py, network.py, osint.py, files.py
- editor.py, images.py, models.py, chat.py, code.py
- multi_agent.py, rag.py, planning.py, delegation.py
- sandbox.py, metrics.py, session.py

### NOT to Migrate (Device-Specific)
| File | Reason |
|------|--------|
| `manager.py` | Different model configurations per device |
| `settings.py` | Different defaults (Ollama port vs llama.cpp) |
| `model_config.py` | Device-specific model lists |
| `device_config.py` | Device-specific hardware settings |

## Migration Steps

1. **Copy files to shared package:**
   ```bash
   cp apps/pkn/backend/tools/*.py packages/pkn-shared/backend/tools/
   ```

2. **Update imports in both apps:**
   ```python
   # Before (in apps/pkn/backend/agents/manager.py)
   from ..tools import code_tools

   # After
   from pkn_shared.backend.tools import code_tools
   ```

3. **Add pkn-shared to Python path:**
   ```python
   # In apps/pkn/backend/server.py
   import sys
   sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "packages"))
   ```

4. **Test both apps:**
   ```bash
   cd apps/pkn && python -c "from backend.tools import code_tools; print('OK')"
   cd apps/pkn-mobile && python -c "from backend.tools import code_tools; print('OK')"
   ```

## Benefits
- Single source of truth for tool modules
- Bug fixes apply to both apps
- Easier maintenance
- Clear separation of shared vs device-specific code
