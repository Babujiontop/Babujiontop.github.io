const express = require("express");
const cors = require("cors");
const app = express();
app.use(express.json());
app.use(cors());

// Handle browser test (GET)
app.get("/api/auth/verify", (req, res) => {
  res.json({ status: "Backend is online! Send a POST request with your Pi token to verify." });
});

// Handle Pi SDK verification (POST)
app.post("/api/auth/verify", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    const accessToken = authHeader && authHeader.split(" ")[1];
    if (!accessToken) {
      return res.status(401).json({ error: "No token provided" });
    }
    const response = await fetch("https://api.minepi.com/v2/me", {
      headers: { "Authorization": "Bearer " + accessToken }
    });
    if (!response.ok) {
      return res.status(401).json({ error: "Pi token verification failed" });
    }
    const piUser = await response.json();
    res.json({ success: true, user: piUser });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(3000, () => console.log("Server running on port 3000"));
