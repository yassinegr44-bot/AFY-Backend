import bcrypt from "bcryptjs";
import type { Request } from "express";
import { q } from "./db.js";

export type User = {
  id: number; username: string; display_name: string;
  role: "ADMIN"|"AGENT"; active: number;
};

export async function authenticate(username: string, password: string) {
  const rows = await q<any[]>("SELECT * FROM users WHERE username=? LIMIT 1", [username]);
  const u = rows[0];
  if (!u || !u.active || !(await bcrypt.compare(password, u.password_hash))) return null;
  return { id:u.id, username:u.username, displayName:u.display_name, role:u.role, active:!!u.active };
}

export function currentUser(req: Request) {
  return (req.session as any).user || null;
}

export function requireUser(req: Request) {
  const u = currentUser(req);
  if (!u) throw new Error("UNAUTHENTICATED");
  return u;
}

export function requireAdmin(req: Request) {
  const u = requireUser(req);
  if (u.role !== "ADMIN") throw new Error("FORBIDDEN");
  return u;
}
