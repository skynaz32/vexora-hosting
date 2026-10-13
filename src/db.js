const { Pool } = require("pg");

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  console.warn("VEXORA: DATABASE_URL is not configured.");
}

const pool = new Pool({
  connectionString,
  ssl: process.env.DATABASE_SSL === "true"
    ? { rejectUnauthorized: true }
    : undefined,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000
});

pool.on("error", (err) => {
  console.error("VEXORA database pool error:", err.message);
});

async function query(text, params) {
  return pool.query(text, params);
}

module.exports = { pool, query };
