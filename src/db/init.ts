import fs from "node:fs";
import { pool } from "../db.js";
const sql=fs.readFileSync(new URL("../../schema.sql",import.meta.url),"utf8");
for(const stmt of sql.split(/;\s*(?=CREATE|USE|$)/i).map(x=>x.trim()).filter(Boolean)){
  await pool.query(stmt);
}
console.log("Database schema ready.");
await pool.end();
