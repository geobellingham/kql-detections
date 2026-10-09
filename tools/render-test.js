#!/usr/bin/env node
// Prints a runnable test for one detection: fixture (synthetic tables) + the rule's query.
// Paste the output into any KQL editor (free Azure Data Explorer cluster, Sentinel Logs, Defender
// advanced hunting) - it uses only datatable/print, no real data - and compare with the EXPECT lines.
// Usage: node tools/render-test.js <rule-folder-name>
const fs = require("fs"), path = require("path"), yaml = require("js-yaml");
const root = path.resolve(__dirname, "..");
const name = process.argv[2];
if (!name) { console.error("usage: node tools/render-test.js <rule-folder-name>"); process.exit(2); }
const find = d => fs.readdirSync(d, { withFileTypes: true }).flatMap(e =>
  e.isDirectory() ? (e.name === name && fs.existsSync(path.join(d, e.name, "rule.yaml")) ? [path.join(d, e.name, "rule.yaml")] : find(path.join(d, e.name))) : []);
const [rulePath] = find(path.join(root, "detections"));
const fixture = path.join(root, "tests", "fixtures", `${name}.kql`);
if (!rulePath || !fs.existsSync(fixture)) { console.error(`no rule or fixture for ${name}`); process.exit(1); }
process.stdout.write(fs.readFileSync(fixture, "utf8") + "\n" + yaml.load(fs.readFileSync(rulePath, "utf8")).query);
