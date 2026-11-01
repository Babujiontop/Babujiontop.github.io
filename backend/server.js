
const http = require("node:http");
const crypto = require("node:crypto");
const { Pool } = require("pg");
const adminSecurity = require("./admin-security");
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

    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin_accounts (
        id BIGSERIAL PRIMARY KEY,
        username VARCHAR(80) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        mfa_secret TEXT NOT NULL,
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS admin_sessions (
        id BIGSERIAL PRIMARY KEY,
        token_hash CHAR(64) UNIQUE NOT NULL,
        admin_id BIGINT NOT NULL REFERENCES admin_accounts(id) ON DELETE CASCADE,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS admin_sessions_expiry_idx
        ON admin_sessions (expires_at);

      CREATE TABLE IF NOT EXISTS admin_recovery_codes (
        id BIGSERIAL PRIMARY KEY,
        admin_id BIGINT NOT NULL REFERENCES admin_accounts(id) ON DELETE CASCADE,
        code_hash CHAR(64) NOT NULL,
        used_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS admin_audit_log (
        id BIGSERIAL PRIMARY KEY,
        admin_id BIGINT REFERENCES admin_accounts(id) ON DELETE SET NULL,
        event_type VARCHAR(80) NOT NULL,
        details JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);
    const encryptionKey = process.env.ADMIN_MFA_ENCRYPTION_KEY;

    if (
      typeof encryptionKey !== "string" ||
      !/^[a-f0-9]{64}$/i.test(encryptionKey)
    ) {
      throw new Error("ADMIN_MFA_ENCRYPTION_KEY is not configured correctly");
    }

    const migrationClient = await pool.connect();

    try {
      await migrationClient.query("BEGIN");

      const admins = await migrationClient.query(
        "SELECT id, mfa_secret FROM admin_accounts FOR UPDATE"
      );

      for (const admin of admins.rows) {
        if (!admin.mfa_secret.startsWith("enc:v1:")) {
          const encryptedSecret =
            adminSecurity.encryptMfaSecret(admin.mfa_secret);

          await migrationClient.query(
            `UPDATE admin_accounts
             SET mfa_secret = $1, updated_at = NOW()
             WHERE id = $2`,
            [encryptedSecret, admin.id]
          );
        }
      }

      await migrationClient.query("COMMIT");
      console.log("Administrator MFA encryption migration completed");
    } catch (error) {
      await migrationClient.query("ROLLBACK");
      throw error;
    } finally {
      migrationClient.release();
    }
  
}
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
  console.log("REQUEST:", req.method, req.url);
  const pathname = new URL(req.url, "http://localhost").pathname.replace(/\/+$/, "") || "/";
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
    res.setHeader(
  "Access-Control-Allow-Headers",
  "Content-Type, X-Admin-Setup-Secret"
);
    res.writeHead(204);
    return res.end();
  }

  
  if (req.method === "GET" && pathname === "/health") {
    return sendJson(res, 200, {
      status: "ok",
      service: "MIXCOFARM MCFT backend"
    });
  }

  if (origin && origin !== ALLOWED_ORIGIN) {
    return sendJson(res, 403, {
      error: "Origin not allowed"
    });
  }
  if (
    req.method === "POST" &&
    pathname === "/api/admin/setup"
  ) {
    if (!pool) {
      return sendJson(res, 503, {
        error: "Database is not configured"
      });
    }

    if (!dbReady && !(await initDatabase())) {
      return sendJson(res, 503, {
        error: "Database is temporarily unavailable"
      });
    }

    const setupSecret = process.env.ADMIN_SETUP_SECRET;
    const suppliedSecret = req.headers["x-admin-setup-secret"];

    if (
      typeof setupSecret !== "string" ||
      setupSecret.length < 32 ||
      !adminSecurity.safeEqual(
        setupSecret,
        typeof suppliedSecret === "string" ? suppliedSecret : ""
      )
    ) {
      return sendJson(res, 403, {
        error: "Setup authorization failed"
      });
    }

    const input = await readJson(req, res, 4096);
    if (input === null) return;

    const username = cleanText(input.username, 80);
    const password = input.password;

    if (!/^[a-zA-Z0-9_.-]{3,80}$/.test(username)) {
      return sendJson(res, 400, {
        error: "Username must be 3–80 characters using letters, numbers, dots, underscores or hyphens"
      });
    }

    if (
      typeof password !== "string" ||
      password.length < 12 ||
      password.length > 1024
    ) {
      return sendJson(res, 400, {
        error: "Password must be 12–1024 characters"
      });
    }

    let client;

    try {
      const passwordHash =
        await adminSecurity.hashPassword(password);

      const mfaSecret =
        adminSecurity.createMfaSecret();
const encryptedMfaSecret =
  adminSecurity.encryptMfaSecret(mfaSecret);
      client = await pool.connect();
      await client.query("BEGIN");

      await client.query(
        "SELECT pg_advisory_xact_lock(48192026)"
      );

      const existing = await client.query(
        "SELECT id FROM admin_accounts LIMIT 1"
      );

      if (existing.rowCount > 0) {
        await client.query("ROLLBACK");
        return sendJson(res, 409, {
          error: "An administrator account already exists"
        });
      }

      const result = await client.query(
        `INSERT INTO admin_accounts
          (username, password_hash, mfa_secret)
         VALUES ($1, $2, $3)
         RETURNING id, username`,
        [username, passwordHash, encryptedMfaSecret]
      );

      await client.query("COMMIT");

      const issuer = "MIXCOFARM MCFT";
      const otpauthUrl =
        "otpauth://totp/" +
        encodeURIComponent(issuer + ":" + username) +
        "?secret=" + mfaSecret +
        "&issuer=" + encodeURIComponent(issuer) +
        "&algorithm=SHA1&digits=6&period=30";

      console.log("Initial administrator account created");

      return sendJson(res, 201, {
        created: true,
        administrator: result.rows[0],
        mfaSecret,
        otpauthUrl,
        message: "Save the MFA secret securely. It will not be shown again."
      });
    } catch (error) {
      if (client) {
        try {
          await client.query("ROLLBACK");
        } catch {}
      }

      console.error("Admin setup failed:", error.message);

      return sendJson(res, 500, {
        error: "Administrator setup failed"
      });
    } finally {
      if (client) client.release();
    }
  }

  if (
    req.method === "POST" &&
    pathname === "/api/auth/verify"
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
    pathname === "/api/merchant/registrations"
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
