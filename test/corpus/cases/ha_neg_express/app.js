const express = require("express");
const app = express();
app.get("/orders", requireAuth, (req, res) => res.json({ orders: [] }));
