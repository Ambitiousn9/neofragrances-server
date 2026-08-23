// db.js — creates a reusable connection pool to MySQL
require("dotenv").config();
const mysql = require("mysql2/promise");

// SSL is required by TiDB Cloud (and most managed MySQL hosts).
// This stays harmless for local MySQL too — if DB_SSL isn't set to "true",
// it just runs with no SSL config, exactly like before.
const useSSL = process.env.DB_SSL === "true";

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10,
  ...(useSSL && {
    ssl: {
      minVersion: "TLSv1.2",
      rejectUnauthorized: true,
    },
  }),
});

module.exports = pool;