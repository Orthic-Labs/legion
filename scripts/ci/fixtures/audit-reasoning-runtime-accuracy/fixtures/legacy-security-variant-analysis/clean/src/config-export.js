const fs = require("node:fs");
const { safePath } = require("./handler");
function exportConfig(req, res) {
  fs.readFile(safePath(req.params.name), "utf8", (error, data) => { if (error) return res.sendStatus(404); res.type("text/plain").send(data); });
}
module.exports = { exportConfig };
