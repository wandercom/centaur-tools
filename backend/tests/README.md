# Backend dependency qualification

From the repository root, using Python 3.12 (the backend container version) or 3.13:

```bash
python -m pip install -r backend/requirements.txt pytest pip-audit
CENTAUR_DATABASE_URL=postgresql+asyncpg://fixture:fixture@127.0.0.1:1/unused \
  PYTHONPATH=. python -m pytest --import-mode=importlib -q backend/tests
python -m pip_audit
```

The maintained tests exercise the real `/api/auth/me`, OAuth callback, logout,
health, and OpenAPI routes. The database and OAuth provider are controlled
collaborators; each test creates a synthetic signing key. No external services
or deployment credentials are required.

The JWT checks cover valid sessions, expiry, signature/algorithm rejection,
malformed subjects, unknown critical headers, explicit bearer precedence,
secure callback cookies and empty-key rejection. Multipart tests exercise the
actual FastAPI/Starlette parsing stack, including file bytes/name preservation,
semicolon handling, missing boundaries and negative content length. Centaur
currently has no upload/form endpoint; that harness qualifies the dependency
integration, not a nonexistent product endpoint.

The repository-root `tests/` directory retains older generated scenarios and
recursive contract scaffolds. Its full collection currently has eight errors
(stale imports, undefined placeholder types, and a truncated generated file),
and some otherwise collectable cases use pre-refactor patch targets or async
mocks for synchronous result accessors. These artifacts are not silently
ignored by a global pytest configuration, deleted, or represented as passing.
The backend workflow explicitly targets the maintained suite above. This is
local dependency compatibility evidence, not live PostgreSQL/OAuth proof.
