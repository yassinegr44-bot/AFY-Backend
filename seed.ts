import bcrypt from "bcryptjs";
import { q,pool } from "../db.js";
import "dotenv/config";
const username=process.env.SEED_ADMIN_USERNAME||"admin";
const password=process.env.SEED_ADMIN_PASSWORD||"ChangeMe123!";
const name=process.env.SEED_ADMIN_NAME||"Administrateur AFY";
const hash=await bcrypt.hash(password,12);
await q(`INSERT INTO users(username,display_name,password_hash,role,active) VALUES(?,?,?,?,1)
ON DUPLICATE KEY UPDATE display_name=VALUES(display_name),role='ADMIN',active=1`,[username,name,hash]);
const raw=(process.env.SEED_FRIGOS||"F01:10,F02:10,F03:10").split(",");
for(const item of raw){const [code,cap]=item.split(":");if(code)await q(`INSERT INTO frigos(code,capacite) VALUES(?,?) ON DUPLICATE KEY UPDATE capacite=VALUES(capacite)`,[code,Number(cap)||10]);}
await q(`INSERT INTO parametres(cle,valeur) VALUES('nom_service','AFY') ON DUPLICATE KEY UPDATE valeur=VALUES(valeur)`);
console.log(`Seed complete. Admin username: ${username}`);
await pool.end();
