
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

app.get("/api/panel", (req, res) => {
  res.json({
    name: "VEXORA HOSTING",
    panels: [
      "customer",
      "staff",
      "admin"
    ],
    features: [
      "bot-hosting",
      "embed-builder",
      "access-management",
      "new-assets",
      "news",
      "advertisements"
    ],
    status: "development"
  });
});

app.get("/api/features", (req, res) => {
  res.json({
    customer: [
      "bot-hosting",
      "embed-builder",
      "new-assets",
      "news"
    ],
    staff: [
      "grant-access",
      "manage-servers",
      "upload-assets",
      "publish-news",
      "manage-advertisements"
    ],
    admin: [
      "manage-users",
      "manage-staff",
      "manage-plans",
      "ban-users",
      "system-settings"
    ],
    note: "Permissions must be enforced by authenticated backend routes."
  });
});

app.get("/api/hosting/status", (req, res) => {
  res.json({
    service: "VEXORA HOSTING",
    hostingEngine: "not-connected",
    totalServers: null,
    runningServers: null,
    ramUsage: null,
    message: "Hosting engine integration is pending."
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`VEXORA HOSTING API listening on port ${PORT}`);
});
