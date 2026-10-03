# LogMind AI — Security Architecture & Assessment

## 1. Security Controls & Protections

| Category | Security Control Implemented |
| :--- | :--- |
| **API Key Protection** | Gemini API key is loaded strictly from environment variables or `.env`. Never rendered in UI, returned in API endpoints, or written to logs. |
| **Input & Path Traversal** | Path canonicalization using `pathlib.Path.resolve()`. File extension whitelist (`.log`, `.txt`, `.json`), 50MB file size limit. |
| **Secret Redaction** | Automated regex pattern filter for API keys, Bearer tokens, DB credentials, AWS keys, and passwords before storage or GenAI submission. |
| **Prompt Injection Defense** | All log content is passed inside `<log_evidence>` tags with explicit system instructions to treat logs as data, not commands. |
| **Database Security** | Parameterized SQLite queries preventing SQL injection. Foreign key constraints enforced via `PRAGMA foreign_keys = ON;`. |

## 2. Best-Effort Disclaimers & Known Limitations

- **Secret Redaction:** Regex redaction is best-effort. Custom obfuscated secrets may not be caught automatically.
- **Remote Deployment:** FastAPI endpoints do not include remote auth out of the box; intended for localhost deployment.
