# Copilot Instructions for llama.cpp-based Codebase

## Project Overview
- This project centers on `llama.cpp`, a high-performance, dependency-free C/C++ implementation for running LLaMA and related models with quantization and multi-platform support.
- Major components include:
  - Core C/C++ inference engine (`llama.cpp`, `ggml.*`, `k_quants.*`)
  - Python/Node/other bindings (see README for links)
  - Example programs: CLI (`main`), HTTP server (`server`), and scripts for chat, quantization, and conversion
  - Support for grammars (GBNF) to constrain model output

## Key Workflows
- **Build:**
  - Use `make` (Linux/macOS) or `cmake` for all platforms. See root and `llama.cpp/README.md` for details.
  - For GPU/BLAS/Metal/CLBlast support, pass the appropriate flags (e.g., `make LLAMA_CUBLAS=1`).
  - Example: `make` or `cmake .. -DLLAMA_CUBLAS=ON`
- **Testing:**
  - Run `bash ./ci/run.sh ./tmp/results ./tmp/mnt` for full CI (CPU or set `GG_BUILD_CUDA=1` for CUDA).
  - Use `ctest` in build directories for unit/integration tests.
- **Inference:**
  - Use `./main` for CLI inference, `./server` for HTTP API (see `examples/server/README.md`).
  - Models must be converted and quantized (see `convert.py`, `quantize`).
  - Example: `./main -m models/7B/ggml-model-q4_0.gguf -p "Prompt" -n 128`
- **Interactive/Chat:**
  - Use `-i`/`--interactive` for chat mode, `-r` for reverse prompts, and `--grammar-file` for output constraints.
  - Persistent chat: see `examples/chat-persistent.sh`.
- **API Usage:**
  - HTTP server exposes `/completion`, `/tokenize`, `/detokenize`, `/embedding` endpoints (see `examples/server/README.md`).

## Project Conventions & Patterns
- **No third-party dependencies** in core C/C++ (keep it portable and minimal).
- **Cross-platform:** Always test on Linux/macOS/Windows; avoid OS-specific code unless guarded.
- **Quantization:** All models should be quantized for efficient inference (see quantization table in README).
- **Grammars:** Use GBNF (`grammars/`) to constrain output; see `grammars/README.md` for syntax and usage.
- **Scripts:** Prefer bash scripts for automation; see `ci/run.sh` for CI, `examples/` for usage patterns.
- **Model files:** Never commit or link to model weights; users must obtain and convert models themselves.
- **Documentation:** Key docs in `README.md` (root, examples, grammars), and `ci/README.md` for CI details.

## Integration Points
- **Python/Node/other bindings:** See links in root README for supported wrappers.
- **HTTP API:** Use `server` binary for RESTful interaction; see `/completion` endpoint for completions.
- **Web UI:** Static files in `examples/server/public` can be extended for custom frontends.

## Examples
- Build with CUDA: `make LLAMA_CUBLAS=1`
- Run chat: `./examples/chat.sh` or `./main -i -m ...`
- Use grammar: `./main --grammar-file grammars/json.gbnf -p 'Prompt'`
- Test server: `curl -X POST http://localhost:8080/completion -d '{"prompt": "Hello"}' -H 'Content-Type: application/json'`

## References
- See `llama.cpp/README.md`, `examples/main/README.md`, `examples/server/README.md`, `grammars/README.md`, and `ci/README.md` for further details and up-to-date options.

---
If any section is unclear or missing project-specific conventions, please provide feedback for further refinement.
