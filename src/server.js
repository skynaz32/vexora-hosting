
const express = require("express");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.get("/", (req, res) => {
  res.json({
    name: "VEXORA HOSTING",
    status: "online",
    message: "VEXORA API is running"
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    service: "vexora-hosting-api"
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`VEXORA HOSTING API listening on port ${PORT}`);
});
