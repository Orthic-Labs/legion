const express = require("express");
const { handleConfig } = require("./handler");
const app = express();
app.get("/config", handleConfig);
const { exportConfig } = require("./config-export");
app.get("/config/export/:name", exportConfig);
app.listen(8080, "0.0.0.0");
