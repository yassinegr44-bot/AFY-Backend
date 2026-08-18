import express from "express";
import cors from "cors";
import session from "express-session";
import { createExpressMiddleware } from "@trpc/server/adapters/express";
import "dotenv/config";
import { appRouter } from "./router.js";

const app = express();
const origin = process.env.CORS_ORIGIN === "*" ? true : (process.env.CORS_ORIGIN || true);
app.set("trust proxy", 1);
app.use(cors({ origin, credentials: true }));
app.use(express.json({ limit: "2mb" }));
app.use(session({
  name: "afy.sid",
  secret: process.env.SESSION_SECRET || "CHANGE_ME",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.CROSS_SITE_COOKIES === "true",
    sameSite: process.env.CROSS_SITE_COOKIES === "true" ? "none" : "lax",
    maxAge: 1000 * 60 * 60 * 12
  }
}));
app.get("/health", (_, res) => res.json({ ok: true, service: "AFY backend" }));
app.use("/api/trpc", createExpressMiddleware({ router: appRouter, createContext: ({ req }) => ({ req }) }));

const port = Number(process.env.PORT || 3000);
app.listen(port, "0.0.0.0", () => {
  console.log(`AFY backend listening on port ${port}`);
});
