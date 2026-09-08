/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Optional: OpenAI/Claude-compatible chat completions endpoint for AI-polished instructions. */
  readonly VITE_AI_ENDPOINT?: string;
  readonly VITE_AI_API_KEY?: string;
  readonly VITE_AI_MODEL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
