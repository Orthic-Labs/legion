const fs = require("node:fs");
const { safePath } = require("./handler");
function exportConfig(req, res) {
  fs.promises.readFile(safePath(req.params.name), "utf8").then((data) => res.type("text/plain").send(data), () => res.sendStatus(404));
}
module.exports = { exportConfig };
