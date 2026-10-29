
"use strict";

const crypto = require("node:crypto");

const SESSION_TTL_MS = 30 * 60 * 1000;
const MFA_WINDOW = 1;

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  const left = Buffer.from(a);
  const right = Buffer.from(b);

  return left.length === right.length &&
    crypto.timingSafeEqual(left, right);
}

async function hashPassword(password) {
  if (typeof password !== "string" || password.length < 12 ||
      password.length > 1024) {
    throw new Error("Password must be 12–1024 characters");
  }

  const salt = crypto.randomBytes(16);
  const derived = await new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (error, key) => {
      if (error) reject(error);
      else resolve(key);
    });
  });

  return [
    "scrypt",
    salt.toString("hex"),
    derived.toString("hex")
  ].join("$");
}

async function verifyPassword(password, stored) {
  if (typeof password !== "string" ||
      typeof stored !== "string") return false;

  const parts = stored.split("$");
  if (parts.length !== 3 || parts[0] !== "scrypt") return false;
  if (!/^[a-f0-9]{32}$/i.test(parts[1]) ||
      !/^[a-f0-9]{128}$/i.test(parts[2])) return false;

  const salt = Buffer.from(parts[1], "hex");
  const expected = Buffer.from(parts[2], "hex");

  const actual = await new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (error, key) => {
      if (error) reject(error);
      else resolve(key);
    });
  });

  return crypto.timingSafeEqual(actual, expected);
}

function base32Encode(buffer) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let output = "";

  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }

  return output;
}

function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = input.toUpperCase().replace(/=+$/g, "");
  let bits = 0;
  let value = 0;
  const output = [];

  for (const char of clean) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error("Invalid MFA secret");

    value = (value << 5) | index;
    bits += 5;

    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return Buffer.from(output);
}

function createMfaSecret() {
  return base32Encode(crypto.randomBytes(20));
}

function totpAt(secret, timeStep) {
  const key = base32Decode(secret);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(timeStep));

  const digest = crypto.createHmac("sha1", key)
    .update(counter)
    .digest();

  const offset = digest[digest.length - 1] & 15;
  const binary = digest.readUInt32BE(offset) & 0x7fffffff;

  return String(binary % 1000000).padStart(6, "0");
}

function verifyTotp(secret, code, now = Date.now()) {
  if (typeof code !== "string" || !/^\d{6}$/.test(code)) {
    return false;
  }

  const step = Math.floor(now / 30000);

  for (let offset = -MFA_WINDOW; offset <= MFA_WINDOW; offset++) {
    if (safeEqual(totpAt(secret, step + offset), code)) {
      return true;
    }
  }

  return false;
}

function createRecoveryCodes(count = 10) {
  if (!Number.isInteger(count) || count < 1 || count > 20) {
    throw new Error("Invalid recovery-code count");
  }

  return Array.from({ length: count }, () =>
    randomToken(9).toUpperCase()
  );
}

function createSessionToken() {
  return randomToken(32);
}

function sessionTokenHash(token) {
  return hashToken(token);
}

function sessionExpiry(now = Date.now()) {
  return new Date(now + SESSION_TTL_MS);
}

module.exports = {
  hashPassword,
  verifyPassword,
  createMfaSecret,
  verifyTotp,
  createRecoveryCodes,
  createSessionToken,
  sessionTokenHash,
  sessionExpiry,
  hashToken,
  safeEqual,
  SESSION_TTL_MS
};
