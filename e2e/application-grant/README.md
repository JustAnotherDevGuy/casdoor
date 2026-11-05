# Cross-organization application grant end-to-end test

Synthetic organizations, users, groups and OAuth clients only (`seed.json`). `run.py` drives
the real HTTP API with the standard library: grant management and its authorization, the
application sign-in page flow (`/api/get-app-login` + `/api/login` with PKCE, state and nonce),
the token, refresh and userinfo endpoints, revocation and the audit records.

    CASDOOR_URL=http://127.0.0.1:8000 CASDOOR_ADMIN_PASSWORD=... ./run.py              # full suite
    CASDOOR_URL=http://127.0.0.1:8000 ./run.py --baseline                               # any version

`--baseline` checks what must hold on any Casdoor version, including a stock release without
grant support and after rolling an upgraded database back to it: internal users sign in with
unchanged claims, refresh works, users of other organizations stay denied.

The `albweb-image` workflow runs the upgrade path on PostgreSQL: stock image → this build →
stock image again on the same database.
