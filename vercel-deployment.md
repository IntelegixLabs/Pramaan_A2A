# Vercel Deployment

Two separate Vercel projects:

| | Folder | URL |
|---|---|---|
| Frontend | `Pramaan_A2A_UI/` | https://pramaan-a2-a-ui.vercel.app |
| Backend | `Pramaan_A2A/` | https://pramaan-a2-a-ug89.vercel.app |

---

## Frontend

- All API calls are wrapped with `apiUrl()` in `src/lib/api.ts`.
- On Vercel, `apiUrl()` uses relative paths (e.g. `/ag-ui/status`), not the backend URL directly.
- `Pramaan_A2A_UI/vercel.json` proxies API paths to the backend. This avoids CORS — the browser only talks to the UI domain.
- Do **not** set `VITE_API_BASE_URL` on Vercel UI. Leave it empty.
- Local dev: leave `VITE_API_BASE_URL` empty. Vite proxies to `VITE_PROXY_URL_BASE` (default `http://localhost:8200`).

**Vercel UI env vars**

- `VITE_APP_NAME` — app title (optional)
- `VITE_API_BASE_URL` — leave empty

**After changing env vars, redeploy the UI.**

---

## Backend

- Deployed with `@vercel/python`. All routes go to `main.py` via `vercel.json`.
- Uses SQLite. Vercel has no persistent disk, so DB files are stored in `/tmp` when `VERCEL=true`:
  - `delegation_ledger.py`, `scan_repository.py`, `dashboard_repository.py` → `/tmp/demo.db`
  - `agent_manager.py` → `/tmp/handshakeos.db`
  - `rag_manager.py` → `/tmp/.ag_chroma`
  - `authorization.py` → `/tmp/policy.rego`
- Data in `/tmp` is **ephemeral** — it resets on each cold start. Fine for demo, not for production persistence.
- CORS middleware added in `main.py` as a fallback for direct cross-origin calls (e.g. localhost → deployed backend). Production UI does not rely on it.

**Vercel backend env vars**

- `OPENAI_API_KEY`, `OPENAI_MODEL` — LLM
- `LANGFUSE_*` — tracing (optional)
- `CORS_ORIGINS` — extra allowed origins, comma-separated (optional)

---

## CORS fix (why production failed)

- UI and backend are on different domains → browser blocks cross-origin requests.
- Opening the backend URL in a new tab works (no CORS).
- Local dev works (Vite proxy = same origin).
- **Fix:** UI calls `/ag-ui/status` on its own domain → Vercel rewrites to the backend.

---

## Deploy

1. Push code.
2. Deploy backend (`Pramaan_A2A`).
3. Deploy frontend (`Pramaan_A2A_UI`) — remove `VITE_API_BASE_URL` if set.
4. Check DevTools → `/ag-ui/status` → Request URL should be `pramaan-a2-a-ui.vercel.app`, not `pramaan-a2-a-ug89`.

---

## If backend URL changes

Update `Pramaan_A2A_UI/vercel.json` (rewrite destinations) and `src/lib/api.ts` (`BACKEND_HOST`). Redeploy UI.
