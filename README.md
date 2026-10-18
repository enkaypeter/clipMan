# clipMan API

## Authentication

New accounts use WorkOS Magic Auth email codes. Existing username/password users can sign in through the legacy endpoint once, link a verified email, and then use email codes. Application users, external identities, pending links, and opaque sessions are stored separately in MongoDB.

Copy `.env.example` to `.env`, add the WorkOS test API key and client ID, and enable Magic Auth in the WorkOS dashboard. For production, serve the API on the same site as the frontend, set `SESSION_COOKIE_SECURE=true`, use an HTTPS origin in `CORS_ALLOW_ORIGINS`, and inject secrets through the deployment secret manager.

```bash
go run .
```

Run the backend suite against the local MongoDB instance:

```bash
go test ./...
```
