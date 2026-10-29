
const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.json({ status: "MIXCOFARM MCFT backend online" });
});

app.get("/api/auth/verify", (req, res) => {
  res.json({
    status: "Backend is online. POST a Pi access token to verify."
  });
});

app.post("/api/auth/verify", async (req, res) => {
  try {
    const { accessToken } = req.body || {};

    if (!accessToken) {
      return res.status(401).json({
        verified: false,
        error: "No Pi access token provided"
      });
    }

    const response = await fetch(
      "https://api.minepi.com/v2/me",
      {
        method: "GET",
        headers: {
          Authorization: `Bearer ${accessToken}`
        }
      }
    );

    if (!response.ok) {
      return res.status(401).json({
        verified: false,
        error: "Pi token verification failed"
      });
    }

    const user = await response.json();

    return res.json({
      verified: true,
      user: {
        uid: user.uid,
        username: user.username
      }
    });

  } catch (error) {
    console.error("Authentication error:", error.message);

    return res.status(500).json({
      verified: false,
      error: "Authentication service error"
    });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`MIXCOFARM backend running on port ${PORT}`);
});
