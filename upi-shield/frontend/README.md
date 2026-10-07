# UPI Shield dashboard

Analyst dashboard for the UPI Shield backend, built with React, TypeScript and Vite.

## Run locally

Start the backend first (see `../README.md`), then:

    npm install
    npm run dev          # http://localhost:5173; /api is proxied to http://localhost:8000

Set `UPI_SHIELD_API_URL` to point the development proxy at another backend.

## Checks

    npm run typecheck
    npm run lint
    npm test
    npm run build        # production bundle in dist/

## Docker

Running `docker compose up --build` in `upi-shield/` serves the dashboard on
http://localhost:8080, and nginx forwards `/api` to the backend container.

## Settings

The analyst name (recorded in the audit trail) and the optional API key (needed when
the backend sets `UPI_SHIELD_API_KEY`) are stored in the browser under **Settings**.
