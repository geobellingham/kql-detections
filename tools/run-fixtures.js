#!/usr/bin/env node
// Runs every detection against its sample data on a real Kusto engine and checks the row count
// in the fixture's "// EXPECT: exactly N rows" line.
// CI starts the Kusto emulator (Kustainer) as a service container. Locally:
//   docker run -d -e ACCEPT_EULA=Y -p 8080:8080 mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
//   node tools/run-fixtures.js [rule-folder-name ...]
// KUSTO_URL overrides the endpoint (default http://localhost:8080).
const fs = require("fs"), path = require("path"), yaml = require("js-yaml");
const root = path.resolve(__dirname, "..");
const url = process.env.KUSTO_URL || "http://localhost:8080";
const inCI = !!process.env.GITHUB_ACTIONS;

const walk = d => fs.readdirSync(d, { withFileTypes: true })
  .flatMap(e => e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]);
const rules = new Map(walk(path.join(root, "detections")).filter(f => f.endsWith("rule.yaml"))
  .map(f => [path.basename(path.dirname(f)), f]));

async function kusto(kind, csl) {
  const res = await fetch(`${url}/v1/rest/${kind}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ db: "NetDefaultDB", csl }),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${text.slice(0, 2000)}`);
  return JSON.parse(text);
}

async function waitForEngine() {
  for (let i = 0; i < 90; i++) {
    try { await kusto("mgmt", ".show version"); return; } catch { await new Promise(r => setTimeout(r, 2000)); }
  }
  throw new Error(`Kusto engine at ${url} did not answer within 3 minutes`);
}

// One line per row with the non-empty columns, so the output can be checked against the EXPECT notes
function describe(table) {
  const cols = table.Columns.map(c => c.ColumnName);
  return table.Rows.map(r => cols.map((c, i) => [c, r[i]])
    .filter(([, v]) => v !== null && v !== "" && !(Array.isArray(v) && v.length === 0))
    .map(([c, v]) => `${c}=${(typeof v === "object" ? JSON.stringify(v) : String(v)).slice(0, 120)}`)
    .join(" | ").slice(0, 1500));
}

const esc = s => s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");

(async () => {
  await waitForEngine();
  const only = process.argv.slice(2);
  const fixtures = walk(path.join(root, "tests", "fixtures")).filter(f => f.endsWith(".kql"))
    .filter(f => !only.length || only.includes(path.basename(f, ".kql"))).sort();
  let failed = 0;
  for (const file of fixtures) {
    const name = path.basename(file, ".kql");
    const fixture = fs.readFileSync(file, "utf8");
    const m = fixture.match(/EXPECT:\s*exactly\s+(\d+)\s+rows?/i);
    let summary, ok;
    try {
      if (!m) throw new Error('no "// EXPECT: exactly N rows" line');
      if (!rules.has(name)) throw new Error(`no detection folder named ${name}`);
      const query = fixture + "\n" + yaml.load(fs.readFileSync(rules.get(name), "utf8")).query;
      const result = await kusto("query", query);
      const table = result.Tables[0];
      const want = Number(m[1]), got = table.Rows.length;
      ok = got === want;
      summary = [`${got} row(s), expected ${want}`, ...describe(table)].join("\n");
    } catch (e) {
      ok = false;
      summary = `error: ${e.message}`;
    }
    if (!ok) failed++;
    console.log(`${ok ? "ok  " : "FAIL"}  ${name}\n${summary.split("\n").map(l => "      " + l).join("\n")}`);
    if (inCI) console.log(`::${ok ? "notice" : "error"} title=${name}::${esc(summary)}`);
  }
  console.log(`\n${fixtures.length - failed}/${fixtures.length} fixtures matched`);
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e.message); process.exit(1); });
