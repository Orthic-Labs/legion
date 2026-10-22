const fs = require("node:fs");
const path = require("node:path");
const ROOT = fs.realpathSync(path.join(__dirname, "public-config"));
function exportConfig(req, res) {
  fs.promises.readFile(path.resolve(ROOT, req.params.name), "utf8").then((data) => res.type("text/plain").send(data), () => res.sendStatus(404));
}
module.exports = { exportConfig };
