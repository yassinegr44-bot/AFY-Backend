# AFY Backend

Backend rebuild compatible with the APK contract extracted from the AFY/Registre des Décès application.

## Includes
- Express + tRPC API at `/api/trpc`
- MySQL schema
- Cookie-based session authentication
- ADMIN / AGENT roles
- 25 requested procedures
- Death records, exits, archiving
- Prise en charge
- Frigos and capacity calculation
- Materiel and panne reporting
- Dashboard/statistics/alerts
- Users, parameters and audit log
- Admin + frigo seed

## Local setup

1. Install Node.js 20+ and MySQL 8+.
2. Copy `.env.example` to `.env`.
3. Set `DATABASE_URL` and a strong `SESSION_SECRET`.
4. Run:
   `npm install`
   `npm run db:push`
   `npm run seed`
   `npm run dev`

Health check:
`GET /health`

The APK should use:
`https://YOUR-DOMAIN/api/trpc`

For HTTPS + cross-site cookies, set:
`CROSS_SITE_COOKIES=true`
and configure `CORS_ORIGIN` to the exact APK/web origin instead of `*`.

Default seed credentials come from `.env`; change them before deployment.
