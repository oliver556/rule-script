const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const templatePath = path.join(root, "script/stoverride/ClashHub_All_Ads.template.yaml");
const outputPath = path.join(root, "script/stoverride/ClashHub_All_Ads.stoverride");

function read(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

function convertRule(line) {
  const raw = line.trim();
  if (!raw || raw.startsWith("#")) return null;

  const parts = raw.split(",").map((item) => item.trim());
  const type = parts[0];

  if (parts.includes("REJECT")) return raw;

  if (type === "IP-CIDR" || type === "IP-CIDR6" || type === "IP-ASN") {
    const hasNoResolve = parts[parts.length - 1] === "no-resolve";
    if (hasNoResolve) return `${parts.slice(0, -1).join(",")},REJECT,no-resolve`;
    return `${raw},REJECT`;
  }

  return `${raw},REJECT`;
}

function includeRules(relativePath) {
  const filePath = path.join(root, relativePath);
  if (!fs.existsSync(filePath)) throw new Error(`Missing rule file: ${relativePath}`);

  return read(filePath)
    .split(/\r?\n/)
    .map(convertRule)
    .filter(Boolean)
    .map((rule) => `  - ${rule}`);
}

function getTopBlock(content, key) {
  const lines = content.split(/\r?\n/);
  const start = lines.findIndex((line) => line === `${key}:`);
  if (start === -1) return [];

  const out = [];
  for (let i = start + 1; i < lines.length; i++) {
    if (/^[A-Za-z0-9_-]+:/.test(lines[i])) break;
    out.push(lines[i]);
  }
  return out;
}

function getHttpChildBlock(content, key) {
  const http = getTopBlock(content, "http");
  const start = http.findIndex((line) => line.trim() === `${key}:`);
  if (start === -1) return [];

  const out = [];
  for (let i = start + 1; i < http.length; i++) {
    if (/^  [A-Za-z0-9_-]+:/.test(http[i])) break;
    out.push(http[i]);
  }
  return out;
}

function normalizeBlock(lines, targetIndent) {
  const nonEmpty = lines.filter((line) => line.trim());
  if (nonEmpty.length === 0) return [];

  const minIndent = Math.min(
    ...nonEmpty.map((line) => line.match(/^ */)[0].length)
  );

  return lines
    .filter((line) => line.trim())
    .map((line) => `${" ".repeat(targetIndent)}${line.slice(minIndent)}`);
}

function collectRules(content, sourceName) {
  const block = getTopBlock(content, "rules");
  const out = [`  # ${sourceName}`];

  for (const line of block) {
    const trimmed = line.trim();

    if (!trimmed) continue;

    if (trimmed.startsWith("# @include-rule ")) {
      const relativePath = trimmed.replace("# @include-rule ", "").trim();
      out.push(...includeRules(relativePath));
      continue;
    }

    if (trimmed.startsWith("- ")) {
      out.push(`  ${trimmed}`);
    }
  }

  return out.length > 1 ? out : [];
}

function collectMitm(content, sourceName, seen) {
  const block = getHttpChildBlock(content, "mitm");
  const items = [];

  for (const line of block) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("- ")) continue;

    const hostname = trimmed.slice(2).trim();
    if (seen.has(hostname)) continue;

    seen.add(hostname);
    items.push(`    - ${hostname}`);
  }

  return items.length ? [`    # ${sourceName}`, ...items] : [];
}

function collectHttpList(content, key, sourceName) {
  const block = normalizeBlock(getHttpChildBlock(content, key), 4);
  return block.length ? [`    # ${sourceName}`, ...block] : [];
}

function collectScriptProviders(content, sourceName, providerMap) {
  const block = normalizeBlock(getTopBlock(content, "script-providers"), 2);
  if (!block.length) return;

  let currentName = null;
  let currentLines = [];

  function flush() {
    if (!currentName) return;

    const existing = providerMap.get(currentName);
    const value = currentLines.join("\n");

    if (existing && existing.value !== value) {
      throw new Error(`Duplicate script-provider with different content: ${currentName}`);
    }

    providerMap.set(currentName, {
      sourceName,
      value,
      lines: currentLines,
    });
  }

  for (const line of block) {
    const match = line.match(/^  ([^#\s][^:]+):\s*$/);

    if (match) {
      flush();
      currentName = match[1];
      currentLines = [line];
    } else if (currentName) {
      currentLines.push(line);
    }
  }

  flush();
}

function parseSources(template) {
  const block = getTopBlock(template, "sources");
  return block
    .map((line) => line.trim())
    .filter((line) => line.startsWith("- "))
    .map((line) => line.slice(2).trim());
}

function buildHeader(template) {
  const lines = template.split(/\r?\n/);
  const out = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (/^(rules|http|script-providers):/.test(line)) {
      break;
    }

    if (line === "sources:") {
      while (i + 1 < lines.length && !/^[A-Za-z0-9_-]+:/.test(lines[i + 1])) {
        i++;
      }
      continue;
    }

    out.push(line);
  }

  return out.join("\n").trimEnd();
}

function build() {
  const template = read(templatePath);
  const sources = parseSources(template);

  if (!sources.length) throw new Error("No sources found in template");

  const rules = [];
  const mitm = [];
  const rewrites = [];
  const scripts = [];
  const mitmSeen = new Set();
  const providerMap = new Map();

  for (const relativePath of sources) {
    const sourcePath = path.join(root, relativePath);
    if (!fs.existsSync(sourcePath)) throw new Error(`Missing source stoverride: ${relativePath}`);

    const content = read(sourcePath);
    const sourceName = path.basename(relativePath, path.extname(relativePath));

    rules.push(...collectRules(content, sourceName));
    mitm.push(...collectMitm(content, sourceName, mitmSeen));
    rewrites.push(...collectHttpList(content, "url-rewrite", sourceName));
    scripts.push(...collectHttpList(content, "script", sourceName));
    collectScriptProviders(content, sourceName, providerMap);
  }

  const output = [];
  output.push(buildHeader(template));
  output.push("");

  if (rules.length) {
    output.push("rules:");
    output.push(...rules);
    output.push("");
  }

  if (mitm.length || rewrites.length || scripts.length) {
    output.push("http:");

    if (mitm.length) {
      output.push("  mitm:");
      output.push(...mitm);
      output.push("");
    }

    if (rewrites.length) {
      output.push("  url-rewrite:");
      output.push(...rewrites);
      output.push("");
    }

    if (scripts.length) {
      output.push("  script:");
      output.push(...scripts);
      output.push("");
    }
  }

  if (providerMap.size) {
    output.push("script-providers:");
    for (const item of providerMap.values()) {
      output.push(`  # ${item.sourceName}`);
      output.push(...item.lines);
    }
    output.push("");
  }

  fs.writeFileSync(outputPath, output.join("\n").replace(/\n{3,}/g, "\n\n"));
  console.log(`Generated: ${outputPath}`);
}

build();