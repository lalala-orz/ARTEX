const fs = require("fs");
const src = fs.readFileSync("page.tsx", "utf8");
// 粗扫：忽略字符串与模板串里的花括号不完美，但足够定位"深度在何处走偏"。
let depth = 0;
const lines = src.split("\n");
let inS = false, inD = false, inT = false, inC = false;
const marks = [];
for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  for (let j = 0; j < line.length; j++) {
    const c = line[j], n = line[j + 1];
    if (inC) { if (c === "*" && n === "/") { inC = false; j++; } continue; }
    if (inS) { if (c === "\\") j++; else if (c === "'") inS = false; continue; }
    if (inD) { if (c === "\\") j++; else if (c === '"') inD = false; continue; }
    if (inT) { if (c === "\\") j++; else if (c === "`") inT = false; continue; }
    if (c === "/" && n === "/") break;
    if (c === "/" && n === "*") { inC = true; j++; continue; }
    if (c === "'") { inS = true; continue; }
    if (c === '"') { inD = true; continue; }
    if (c === "`") { inT = true; continue; }
    if (c === "{" || c === "(") { depth++; continue; }
    if (c === "}" || c === ")") { depth--; if (depth < 0) { console.log("深度变负 @ 行", i + 1); i = lines.length; break; } }
  }
  if (i % 40 === 0) marks.push([i + 1, depth]);
}
console.log("最终深度 =", depth);
for (const [ln, dp] of marks) console.log("  行", ln, "深度", dp);
console.log("末尾 12 行深度:", JSON.stringify(marks.slice(-12)));