const fs = require("node:fs");
function exportConfig(req, res) {
  fs.readFile(req.params.name, "utf8", (error, data) => { if (error) return res.sendStatus(404); res.type("text/plain").send(data); });
}
module.exports = { exportConfig };
