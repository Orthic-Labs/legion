const express = require("express");
const { handleConfig } = require("./handler");
const app = express();
app.get("/config", handleConfig);
app.listen(8080, "0.0.0.0");
