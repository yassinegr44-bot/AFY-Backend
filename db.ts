import mysql from "mysql2/promise";
import "dotenv/config";

const url = new URL(process.env.DATABASE_URL || "mysql://root@127.0.0.1:3306/afy");

export const pool = mysql.createPool({
  host: url.hostname,
  port: Number(url.port || 3306),
  user: decodeURIComponent(url.username),
  password: decodeURIComponent(url.password),
  database: url.pathname.replace(/^\//, ""),
  waitForConnections: true,
  connectionLimit: 10,
  charset: "utf8mb4"
});

export async function q<T = any>(sql: string, params: any[] = []): Promise<T> {
  const [rows] = await pool.query(sql, params);
  return rows as T;
}
