
const http = require("node:http");
const crypto = require("node:crypto");
const { Pool } = require("pg");

const PORT = Number(process.env.PORT || 3000);
const ALLOWED_ORIGIN = "https://babujiontop.github.io";
const PI_ME_URL = "https://api.minepi.com/v2/me";

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      max: 5,
      connectionTimeoutMillis: 10000,
      idleTimeoutMillis: 30000
    })
  : null;

let dbReady = false;

async function initDatabase() {
  if (!pool) {
    console.error("DATABASE_URL is not configured");
    return false;
  }

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS merchant_registrations (
        id BIGSERIAL PRIMARY KEY,
        reference TEXT UNIQUE NOT NULL,
        owner_name VARCHAR(80) NOT NULL,
        business_name VARCHAR(100) NOT NULL,
        category VARCHAR(100) NOT NULL,
        country VARCHAR(50) NOT NULL,
        email VARCHAR(120),
        phone VARCHAR(30),
        city VARCHAR(100),
        description VARCHAR(500),
        consent BOOLEAN NOT NULL DEFAULT FALSE,
        status VARCHAR(30) NOT NULL DEFAULT 'pending_review',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    dbReady = true;
    console.log("Merchant registration database is ready");
    return true;
  } catch (error) {
    dbReady = false;
    console.error("Database initialization failed:", error.message);
    return false;
  }
}

initDatabase();

function sendJson(res, status, data) {
  res.writeHead(status);
  res.end(JSON.stringify(data));
}

async function readJson(req, res, maxBytes = 12000) {
  let body = "";

  for await (const chunk of req) {
    body += chunk.toString("utf8");

    if (Buffer.byteLength(body, "utf8") > maxBytes) {
      sendJson(res, 413, { error: "Request too large" });
      return null;
    }
  }

  try {
    return JSON.parse(body);
  } catch {
    sendJson(res, 400, { error: "Invalid JSON" });
    return null;
  }
}

function cleanText(value, maxLength) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maxLength);
}

const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin;

  res.setHeader("Vary", "Origin");
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Cache-Control", "no-store");

  if (origin === ALLOWED_ORIGIN) {
    res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  }

  if (req.method === "OPTIONS") {
    if (origin !== ALLOWED_ORIGIN) {
      return sendJson(res, 403, { error: "Origin not allowed" });
    }

    res.setHeader(
      "Access-Control-Allow-Methods",
      "GET, POST, OPTIONS"
    );
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    res.writeHead(204);
    return res.end();
  }

  if (req.method === "GET" && req.url === "/health") {
    return sendJson(res, 200, {
      status: "ok",
      service: "MIXCOFARM MCFT backend"
    });
  }

  if (origin !== ALLOWED_ORIGIN) {
    return sendJson(res, 403, { error: "Origin not allowed" });
  }

  if (
    req.method === "POST" &&
    req.url === "/api/auth/verify"
  ) {
    const input = await readJson(req, res, 8192);
    if (input === null) return;

    const accessToken = input && input.accessToken;

    if (
      typeof accessToken !== "string" ||
      accessToken.length < 1 ||
      accessToken.length > 4096
    ) {
      return sendJson(res, 400, {
        error: "Access token required"
      });
    }

    try {
      const piResponse = await fetch(PI_ME_URL, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/json"
        },
        signal: AbortSignal.timeout(10000)
      });

      if (!piResponse.ok) {
        return sendJson(res, 401, {
          error: "Pi authentication could not be verified"
        });
      }

      const user = await piResponse.json();

      if (
        !user ||
        typeof user.uid !== "string" ||
        typeof user.username !== "string"
      ) {
        return sendJson(res, 502, {
          error: "Unexpected response from Pi"
        });
      }

      return sendJson(res, 200, {
        verified: true,
        user: {
          uid: user.uid,
          username: user.username
        }
      });
    } catch {
      return sendJson(res, 502, {
        error: "Pi verification service is temporarily unavailable"
      });
    }
  }

  if (
    req.method === "POST" &&
    req.url === "/api/merchant/registrations"
  ) {
    if (!pool) {
      return sendJson(res, 503, {
        error: "Registration database is not configured"
      });
    }

    if (!dbReady && !(await initDatabase())) {
      return sendJson(res, 503, {
        error: "Registration database is temporarily unavailable"
      });
    }

    const input = await readJson(req, res);
    if (input === null) return;

    const owner = cleanText(input.owner, 80);
    const store = cleanText(input.store, 100);
    const category = cleanText(input.category, 100);
    const country = cleanText(input.country, 50);
    const email = cleanText(input.email, 120);
    const phone = cleanText(input.phone, 30);
    const city = cleanText(input.location, 100);
    const description = cleanText(input.description, 500);

    if (!owner || !store || !category || !country) {
      return sendJson(res, 400, {
        error: "Owner, business name, category and country are required"
      });
    }

    if (input.consent !== true) {
      return sendJson(res, 400, {
        error: "Demo consent is required"
      });
    }

    if (
      email &&
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    ) {
      return sendJson(res, 400, {
        error: "Please provide a valid email address"
      });
    }

    const reference =
      "MCD-" +
      Date.now().toString(36).toUpperCase() +
      crypto.randomBytes(3).toString("hex").toUpperCase();

    try {
      await pool.query(
        `INSERT INTO merchant_registrations
          (reference, owner_name, business_name, category,
           country, email, phone, city, description, consent)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [
          reference,
          owner,
          store,
          category,
          country,
          email || null,
          phone || null,
          city || null,
          description || null,
          true
        ]
      );

      return sendJson(res, 201, {
        saved: true,
        reference,
        status: "pending_review",
        message: "Demo registration saved successfully"
      });
    } catch (error) {
      console.error("Registration save failed:", error.message);
      return sendJson(res, 500, {
        error: "Could not save registration. Please try again later."
      });
    }
  }

  return sendJson(res, 404, { error: "Not found" });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`MIXCOFARM backend listening on port ${PORT}`);
});
