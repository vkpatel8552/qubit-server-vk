# Qubit Server

Backend for the Qubit QA Platform — deployed on Render.

## Endpoints
- `POST /api/auth/register` — register user
- `POST /api/auth/login` — sign in
- `POST /api/connectors/jira/connect` — link Jira
- `POST /api/testplan/generate` — generate test plan (SSE stream)
- `GET /api/health` — health check

## Environment variables
See Render dashboard. Required: `PORT`, `CORS_ORIGIN`, `JWT_SECRET`, `ALLOWED_DOMAINS`.