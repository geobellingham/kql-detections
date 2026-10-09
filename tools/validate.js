#!/usr/bin/env node
// Validates every detection in the repo:
//   1. rule.yaml has the required Sentinel analytic-rule fields and a unique id
//   2. the KQL parses and binds against tools/schemas.json (Microsoft's Kusto.Language parser)
// Hunting queries (*.kql under hunting/) get the KQL check only.
//
// Usage: npm ci --prefix tools && node tools/validate.js
const fs = require("fs");
const path = require("path");
const yaml = require("js-yaml");

const root = path.resolve(__dirname, "..");
const ksBase = path.dirname(require.resolve("@kusto/language-service-next/package.json"));
global.Bridge = require(path.join(ksBase, "bridge.js"));
require(path.join(ksBase, "Kusto.Language.Bridge.js"));
const K = global.Kusto.Language;

// ---- schema -------------------------------------------------------------
const schemas = JSON.parse(fs.readFileSync(path.join(__dirname, "schemas.json"), "utf8"));
const tables = Object.entries(schemas).map(([name, cols]) =>
  new K.Symbols.TableSymbol.$ctor7(name, "(" + Object.entries(cols).map(([c, t]) => `${c}:${t}`).join(", ") + ")", null));
const db = new K.Symbols.DatabaseSymbol.ctor("Sentinel", tables);
const globals = K.GlobalState.Default
  .WithCluster(new K.Symbols.ClusterSymbol.ctor("local", [db]))
  .WithDatabase(db);

// Sentinel built-in functions the parser doesn't know about, stubbed with their output shape.
const STUBS = {
  _GetWatchlist: "let _GetWatchlist = (alias: string) { datatable(SearchKey: string, UserPrincipalName: string, LeaveDate: datetime)[] };\n",
};

function checkKql(text) {
  let prefix = "";
  for (const [fn, stub] of Object.entries(STUBS)) if (text.includes(fn)) prefix += stub;
  const full = prefix + text;
  const code = K.KustoCode.ParseAndAnalyze(full, globals);
  const diags = code.GetDiagnostics();
  const errors = [];
  for (let i = 0; i < diags.Count; i++) {
    const d = diags.getItem(i);
    if (d.Severity !== "Error") continue;
    const pos = d.Start - prefix.length;
    const line = text.slice(0, Math.max(pos, 0)).split("\n").length;
    errors.push(`line ${line}: ${d.Message}`);
  }
  return errors;
}

// ---- rule metadata --------------------------------------------------------
const REQUIRED = ["id", "name", "description", "severity", "requiredDataConnectors", "queryFrequency",
  "queryPeriod", "triggerOperator", "triggerThreshold", "tactics", "relevantTechniques", "query", "version", "kind"];
const SEVERITIES = ["Informational", "Low", "Medium", "High"];
const ids = new Map();

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out); else out.push(p);
  }
  return out;
}

let failures = 0, checked = 0;
const report = (file, errs) => {
  checked++;
  const rel = path.relative(root, file);
  if (errs.length) { failures++; console.log(`FAIL  ${rel}`); errs.forEach(e => console.log(`      ${e}`)); }
  else console.log(`ok    ${rel}`);
};

for (const file of walk(path.join(root, "detections")).filter(f => f.endsWith("rule.yaml"))) {
  const errs = [];
  let rule;
  try { rule = yaml.load(fs.readFileSync(file, "utf8")); } catch (e) { report(file, [`YAML: ${e.message}`]); continue; }
  for (const k of REQUIRED) if (rule[k] === undefined) errs.push(`missing field: ${k}`);
  if (rule.severity && !SEVERITIES.includes(rule.severity)) errs.push(`bad severity: ${rule.severity}`);
  if (rule.id) {
    if (ids.has(rule.id)) errs.push(`duplicate id with ${ids.get(rule.id)}`);
    ids.set(rule.id, path.relative(root, file));
  }
  if (!fs.existsSync(path.join(path.dirname(file), "README.md"))) errs.push("missing README.md (ADS write-up)");
  if (rule.query) errs.push(...checkKql(rule.query));
  report(file, errs);
}

const huntDir = path.join(root, "hunting");
if (fs.existsSync(huntDir))
  for (const file of walk(huntDir).filter(f => f.endsWith(".kql")))
    report(file, checkKql(fs.readFileSync(file, "utf8")));

console.log(`\n${checked - failures}/${checked} passed`);
process.exit(failures ? 1 : 0);
