const fs = require("node:fs");
const path = require("node:path");
const ROOT = fs.realpathSync(path.join(__dirname, "public-config"));
function safePath(input) {
  const resolved = fs.realpathSync(path.resolve(ROOT, input));
  if (resolved !== ROOT && !resolved.startsWith(ROOT + path.sep)) throw new Error("path escapes root");
  return resolved;
}
function handleConfig(req, res) {
  fs.readFile(safePath(req.query.path), "utf8", (error, data) => { if (error) return res.sendStatus(404); res.type("text/plain").send(data); });
}
module.exports = { handleConfig, safePath };
