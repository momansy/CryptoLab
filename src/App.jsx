import React, { useEffect, useMemo, useState } from "react";

const tools = [
  { id: "sdes", title: "S-DES Calculator", group: "Symmetric" },
  { id: "rsa", title: "RSA Step-by-Step", group: "Public Key" },
  { id: "dh", title: "Diffie-Hellman", group: "Public Key" },
  { id: "mod", title: "Modular Math Lab", group: "Number Theory" },
  { id: "caesar", title: "Caesar Cipher", group: "Classical" },
  { id: "columnar", title: "Columnar Transposition", group: "Classical" },
  { id: "hash", title: "Hash Avalanche Demo", group: "Hashing" },
  { id: "tls", title: "TLS Interactive Lab", group: "Network Security" },
];

function cleanBinary(value, length) {
  const v = String(value || "").replace(/[^01]/g, "");
  return v.slice(0, length);
}

function isBinary(value, length) {
  return /^[01]+$/.test(value) && value.length === length;
}

function permute(bits, order) {
  return order.map((i) => bits[i - 1]).join("");
}

function leftShift(bits, count) {
  return bits.slice(count) + bits.slice(0, count);
}

function xorBits(a, b) {
  return a
    .split("")
    .map((x, i) => (x === b[i] ? "0" : "1"))
    .join("");
}

function sboxLookup(bits, box) {
  const row = parseInt(bits[0] + bits[3], 2);
  const col = parseInt(bits[1] + bits[2], 2);
  return box[row][col].toString(2).padStart(2, "0");
}

function generateSdesTrace(input, key, mode) {
  const P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6];
  const P8 = [6, 3, 7, 4, 8, 5, 10, 9];
  const IP = [2, 6, 3, 1, 4, 8, 5, 7];
  const IP_INV = [4, 1, 3, 5, 7, 2, 8, 6];
  const EP = [4, 1, 2, 3, 2, 3, 4, 1];
  const P4 = [2, 4, 3, 1];
  const S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2],
  ];
  const S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3],
  ];

  const trace = [];
  const add = (title, value, note = "") => trace.push({ title, value, note });

  add("Original 10-bit key", key, "The user key before generating subkeys.");
  const p10 = permute(key, P10);
  add("P10 permutation", p10, "Reorders the 10 key bits using P10.");
  let left = p10.slice(0, 5);
  let right = p10.slice(5);
  add("Split key", `${left} | ${right}`, "The key is divided into two 5-bit halves.");

  left = leftShift(left, 1);
  right = leftShift(right, 1);
  add("LS-1", `${left} | ${right}`, "Each half is shifted left by one position.");
  const k1 = permute(left + right, P8);
  add("K1 = P8", k1, "P8 selects and reorders 8 bits to generate K1.");

  left = leftShift(left, 2);
  right = leftShift(right, 2);
  add("LS-2", `${left} | ${right}`, "Each half is shifted left by two more positions.");
  const k2 = permute(left + right, P8);
  add("K2 = P8", k2, "P8 is applied again to generate K2.");

  const firstKey = mode === "encrypt" ? k1 : k2;
  const secondKey = mode === "encrypt" ? k2 : k1;
  add("Round key order", `${firstKey}, then ${secondKey}`, mode === "encrypt" ? "Encryption uses K1 then K2." : "Decryption uses K2 then K1.");

  function fk(bits, roundKey, roundName) {
    const L = bits.slice(0, 4);
    const R = bits.slice(4);
    add(`${roundName}: Split`, `${L} | ${R}`, "Left and right halves before the Feistel function.");
    const ep = permute(R, EP);
    add(`${roundName}: E/P`, ep, "The right half is expanded from 4 bits to 8 bits.");
    const xored = xorBits(ep, roundKey);
    add(`${roundName}: XOR with subkey`, `${ep} XOR ${roundKey} = ${xored}`, "The expanded right half is mixed with the round key.");
    const left4 = xored.slice(0, 4);
    const right4 = xored.slice(4);
    const s0Out = sboxLookup(left4, S0);
    const s1Out = sboxLookup(right4, S1);
    add(`${roundName}: S-boxes`, `S0(${left4})=${s0Out}, S1(${right4})=${s1Out}`, "Each 4-bit part is compressed into 2 bits using S-boxes.");
    const p4 = permute(s0Out + s1Out, P4);
    add(`${roundName}: P4`, p4, "The 4 S-box output bits are permuted.");
    const newLeft = xorBits(L, p4);
    add(`${roundName}: Left XOR P4`, `${L} XOR ${p4} = ${newLeft}`, "The P4 result is XORed with the left half.");
    return newLeft + R;
  }

  add("Input block", input, mode === "encrypt" ? "This is the plaintext block." : "This is the ciphertext block.");
  const ip = permute(input, IP);
  add("Initial Permutation IP", ip, "The 8-bit input is reordered before the rounds.");
  const afterRound1 = fk(ip, firstKey, "Round 1");
  add("After Round 1", afterRound1, "Output after applying the first Feistel round.");
  const switched = afterRound1.slice(4) + afterRound1.slice(0, 4);
  add("Switch halves", switched, "The left and right halves are swapped before round 2.");
  const afterRound2 = fk(switched, secondKey, "Round 2");
  add("After Round 2", afterRound2, "Output after the second Feistel round.");
  const result = permute(afterRound2, IP_INV);
  add("Inverse IP", result, mode === "encrypt" ? "Final ciphertext." : "Final plaintext.");

  return { trace, result, k1, k2 };
}

function egcdNumber(a, b) {
  let oldR = a;
  let r = b;
  let oldS = 1;
  let s = 0;
  let oldT = 0;
  let t = 1;
  const rows = [];
  while (r !== 0) {
    const q = Math.floor(oldR / r);
    rows.push({ q, oldR, r, oldS, s, oldT, t });
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
    [oldT, t] = [t, oldT - q * t];
  }
  return { gcd: Math.abs(oldR), x: oldS, y: oldT, rows };
}

function modInverseNumber(a, m) {
  const normalized = ((a % m) + m) % m;
  const r = egcdNumber(normalized, m);
  if (r.gcd !== 1) return null;
  return ((r.x % m) + m) % m;
}

function bigModPow(base, exp, mod) {
  let b = BigInt(base);
  let e = BigInt(exp);
  const m = BigInt(mod);
  if (m === 0n) return { result: 0n, steps: [] };
  b = ((b % m) + m) % m;
  let result = 1n;
  const steps = [];
  while (e > 0n) {
    const bit = e % 2n === 1n ? 1 : 0;
    const before = result;
    if (bit) result = (result * b) % m;
    steps.push({ bit, before, base: b, after: result });
    b = (b * b) % m;
    e = e / 2n;
  }
  return { result, steps };
}

function isPrimeSmall(n) {
  if (n < 2) return false;
  for (let i = 2; i * i <= n; i++) if (n % i === 0) return false;
  return true;
}

function alphabetIndex(ch) {
  return ch.toUpperCase().charCodeAt(0) - 65;
}

function fromAlphabetIndex(i) {
  return String.fromCharCode(((i % 26) + 26) % 26 + 65);
}

function caesarTransform(text, shift, mode) {
  const s = Number(shift) || 0;
  const actual = mode === "encrypt" ? s : -s;
  const rows = [];
  const output = text
    .split("")
    .map((ch) => {
      if (!/[a-z]/i.test(ch)) return ch;
      const lower = ch === ch.toLowerCase();
      const x = alphabetIndex(ch);
      const y = ((x + actual) % 26 + 26) % 26;
      const out = fromAlphabetIndex(y);
      rows.push({
        input: ch,
        number: x,
        operation: `(${x} ${actual >= 0 ? "+" : "-"} ${Math.abs(actual)}) mod 26`,
        output: lower ? out.toLowerCase() : out,
      });
      return lower ? out.toLowerCase() : out;
    })
    .join("");
  return { output, rows };
}

function parseNumericKey(key) {
  const raw = String(key || "").trim();
  if (!raw) return { numbers: [], error: "Enter a numeric key order." };

  const tokens = raw.match(/[0-9]+/g) || [];
  const parts = tokens.length === 1 && tokens[0] === raw ? raw.split("") : tokens;
  const numbers = parts.map((part) => Number(part));

  if (numbers.length === 0 || numbers.some((num) => !Number.isInteger(num) || num <= 0)) {
    return { numbers, error: "The key must contain positive numbers only." };
  }

  const size = numbers.length;
  const unique = new Set(numbers);
  if (unique.size !== size) return { numbers, error: "The numeric key cannot contain repeated numbers." };

  for (let i = 1; i <= size; i++) {
    if (!unique.has(i)) return { numbers, error: `The key must be a complete order from 1 to ${size}.` };
  }

  return { numbers, error: "" };
}

function columnOrderFromKey(key) {
  const parsed = parseNumericKey(key);
  if (parsed.error) return { order: [], numbers: parsed.numbers, error: parsed.error };
  const order = parsed.numbers
    .map((rank, idx) => ({ idx, rank }))
    .sort((a, b) => a.rank - b.rank);
  return { order, numbers: parsed.numbers, error: "" };
}

function columnarEncrypt(text, key) {
  const clean = text.toUpperCase().replace(/[^A-Z]/g, "");
  const parsed = columnOrderFromKey(key);
  if (parsed.error) return { output: "", grid: [], order: [], numbers: parsed.numbers, error: parsed.error };
  const cols = parsed.numbers.length;
  const rowsCount = Math.ceil(clean.length / cols);
  const padded = clean.padEnd(rowsCount * cols, "X");
  const grid = [];
  for (let r = 0; r < rowsCount; r++) grid.push(padded.slice(r * cols, r * cols + cols).split(""));
  let output = "";
  for (const col of parsed.order) for (let r = 0; r < rowsCount; r++) output += grid[r][col.idx];
  return { output, grid, order: parsed.order, numbers: parsed.numbers, error: "" };
}

function columnarDecrypt(cipher, key) {
  const clean = cipher.toUpperCase().replace(/[^A-Z]/g, "");
  const parsed = columnOrderFromKey(key);
  if (parsed.error || clean.length === 0) return { output: "", grid: [], order: [], numbers: parsed.numbers, error: parsed.error };
  const cols = parsed.numbers.length;
  const rowsCount = Math.ceil(clean.length / cols);
  const total = rowsCount * cols;
  const padded = clean.padEnd(total, "X");
  const grid = Array.from({ length: rowsCount }, () => Array(cols).fill(""));
  let pos = 0;
  for (const col of parsed.order) {
    for (let r = 0; r < rowsCount; r++) grid[r][col.idx] = padded[pos++];
  }
  const output = grid.map((row) => row.join("")).join("").replace(/X+$/g, "");
  return { output, grid, order: parsed.order, numbers: parsed.numbers, error: "" };
}

async function sha256Hex(text) {
  if (!window.crypto?.subtle) return "SHA-256 is not available in this browser.";
  const data = new TextEncoder().encode(text);
  const digest = await window.crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBinary(hex) {
  if (!/^[0-9a-f]+$/i.test(hex)) return "";
  return hex
    .split("")
    .map((h) => parseInt(h, 16).toString(2).padStart(4, "0"))
    .join("");
}

function hammingDistance(a, b) {
  const A = hexToBinary(a);
  const B = hexToBinary(b);
  if (!A || !B || A.length !== B.length) return 0;
  let count = 0;
  for (let i = 0; i < A.length; i++) if (A[i] !== B[i]) count++;
  return count;
}

function Shell({ children, active, setActive }) {
  const groups = [...new Set(tools.map((t) => t.group))];
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto flex max-w-7xl gap-5 px-4 py-5">
        <aside className="sticky top-5 hidden h-[calc(100vh-40px)] w-72 shrink-0 overflow-auto rounded-3xl border border-white/10 bg-white/[0.04] p-4 shadow-2xl lg:block">
          <div className="mb-6 rounded-2xl bg-gradient-to-br from-slate-800 to-slate-900 p-4">
            <h1 className="text-2xl font-bold tracking-tight">CryptoLab</h1>
            <p className="mt-2 text-sm text-slate-300">Interactive cryptography course toolkit</p>
          </div>
          {groups.map((group) => (
            <div key={group} className="mb-5">
              <div className="mb-2 px-2 text-xs font-semibold uppercase tracking-wider text-slate-400">{group}</div>
              <div className="space-y-1">
                {tools
                  .filter((t) => t.group === group)
                  .map((tool) => (
                    <button
                      key={tool.id}
                      onClick={() => setActive(tool.id)}
                      className={`w-full rounded-2xl px-3 py-2 text-left text-sm transition ${
                        active === tool.id ? "bg-cyan-400 text-slate-950 shadow-lg shadow-cyan-400/20" : "text-slate-200 hover:bg-white/10"
                      }`}
                    >
                      {tool.title}
                    </button>
                  ))}
              </div>
            </div>
          ))}
        </aside>
        <main className="min-w-0 flex-1">
          <div className="mb-4 rounded-3xl border border-white/10 bg-white/[0.04] p-4 shadow-2xl lg:hidden">
            <h1 className="text-2xl font-bold">CryptoLab</h1>
            <select value={active} onChange={(e) => setActive(e.target.value)} className="mt-3 w-full rounded-xl bg-slate-900 p-3 text-slate-100 outline-none ring-1 ring-white/10">
              {tools.map((t) => (
                <option key={t.id} value={t.id}>{`${t.group} - ${t.title}`}</option>
              ))}
            </select>
          </div>
          {children}
        </main>
      </div>
    </div>
  );
}

function Panel({ title, subtitle, children }) {
  return (
    <section className="rounded-3xl border border-white/10 bg-white/[0.04] p-5 shadow-2xl">
      <div className="mb-5">
        <h2 className="text-3xl font-bold tracking-tight">{title}</h2>
        {subtitle && <p className="mt-2 text-slate-300">{subtitle}</p>}
      </div>
      {children}
    </section>
  );
}

function Input({ label, value, onChange, placeholder, type = "text" }) {
  return (
    <label className="block">
      <span className="mb-1 block text-sm font-medium text-slate-300">{label}</span>
      <input
        type={type}
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        className="w-full rounded-2xl border border-white/10 bg-slate-900 px-4 py-3 text-slate-100 outline-none transition placeholder:text-slate-500 focus:border-cyan-300"
      />
    </label>
  );
}

function Select({ label, value, onChange, children }) {
  return (
    <label className="block">
      <span className="mb-1 block text-sm font-medium text-slate-300">{label}</span>
      <select value={value} onChange={(e) => onChange(e.target.value)} className="w-full rounded-2xl border border-white/10 bg-slate-900 px-4 py-3 text-slate-100 outline-none transition focus:border-cyan-300">
        {children}
      </select>
    </label>
  );
}

function ResultBox({ label, value }) {
  return (
    <div className="rounded-2xl border border-cyan-300/20 bg-cyan-300/10 p-4">
      <div className="text-sm font-medium text-cyan-200">{label}</div>
      <div className="mt-1 break-all font-mono text-2xl font-bold text-cyan-50">{value}</div>
    </div>
  );
}

function TraceList({ trace }) {
  return (
    <div className="space-y-3">
      {trace.map((step, index) => (
        <div key={`${step.title}-${index}`} className="rounded-2xl border border-white/10 bg-slate-900/70 p-4">
          <div className="flex items-start gap-3">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-slate-700 text-sm font-bold">{index + 1}</div>
            <div className="min-w-0 flex-1">
              <div className="font-semibold text-slate-100">{step.title}</div>
              <div className="mt-1 break-all rounded-xl bg-black/30 px-3 py-2 font-mono text-cyan-200">{step.value}</div>
              {step.note && <p className="mt-2 text-sm text-slate-400">{step.note}</p>}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

function SdesTool() {
  const [input, setInput] = useState("10101010");
  const [key, setKey] = useState("1010000010");
  const [mode, setMode] = useState("encrypt");
  const cleanInput = cleanBinary(input, 8);
  const cleanKey = cleanBinary(key, 10);
  const valid = isBinary(cleanInput, 8) && isBinary(cleanKey, 10);
  const output = valid ? generateSdesTrace(cleanInput, cleanKey, mode) : null;

  return (
    <Panel title="S-DES Calculator" subtitle="Enter an 8-bit block and a 10-bit key. The calculator traces key generation and both Feistel rounds.">
      <div className="grid gap-4 lg:grid-cols-3">
        <Input label={mode === "encrypt" ? "Plaintext, 8 bits" : "Ciphertext, 8 bits"} value={cleanInput} onChange={setInput} placeholder="10101010" />
        <Input label="Key, 10 bits" value={cleanKey} onChange={setKey} placeholder="1010000010" />
        <Select label="Mode" value={mode} onChange={setMode}>
          <option value="encrypt">Encrypt</option>
          <option value="decrypt">Decrypt</option>
        </Select>
      </div>
      {!valid && <div className="mt-4 rounded-2xl bg-rose-500/10 p-4 text-rose-200">Use exactly 8 binary bits for the block and exactly 10 binary bits for the key.</div>}
      {output && (
        <div className="mt-5 grid gap-5 xl:grid-cols-[320px_1fr]">
          <div className="space-y-4">
            <ResultBox label="Final result" value={output.result} />
            <div className="rounded-2xl border border-white/10 bg-slate-900/70 p-4">
              <div className="text-sm text-slate-400">Generated subkeys</div>
              <div className="mt-3 grid grid-cols-2 gap-3 font-mono">
                <div className="rounded-xl bg-white/5 p-3">K1<br /><span className="text-cyan-200">{output.k1}</span></div>
                <div className="rounded-xl bg-white/5 p-3">K2<br /><span className="text-cyan-200">{output.k2}</span></div>
              </div>
            </div>
          </div>
          <TraceList trace={output.trace} />
        </div>
      )}
    </Panel>
  );
}

function RsaTool() {
  const [p, setP] = useState("11");
  const [q, setQ] = useState("17");
  const [e, setE] = useState("7");
  const [m, setM] = useState("88");
  const P = Number(p);
  const Q = Number(q);
  const E = Number(e);
  const M = Number(m);
  const validNums = Number.isInteger(P) && Number.isInteger(Q) && Number.isInteger(E) && Number.isInteger(M) && P > 1 && Q > 1 && E > 1 && M >= 0;
  const n = validNums ? P * Q : 0;
  const phi = validNums ? (P - 1) * (Q - 1) : 0;
  const gcdE = validNums ? egcdNumber(E, phi).gcd : 0;
  const d = validNums ? modInverseNumber(E, phi) : null;
  const canRun = validNums && d !== null && M < n;
  const cipher = canRun ? bigModPow(M, E, n).result.toString() : "-";
  const decrypted = canRun ? bigModPow(cipher, d, n).result.toString() : "-";
  const trace = canRun
    ? [
        { title: "Choose primes", value: `p=${P}, q=${Q}`, note: isPrimeSmall(P) && isPrimeSmall(Q) ? "Both inputs are prime for this example." : "Warning: at least one input is not prime, so this is not a proper RSA setup." },
        { title: "Compute n", value: `n = p * q = ${P} * ${Q} = ${n}`, note: "n is the public modulus." },
        { title: "Compute Euler phi", value: `phi(n) = (p-1)(q-1) = ${P - 1} * ${Q - 1} = ${phi}`, note: "This works because p and q should be prime." },
        { title: "Check public exponent", value: `gcd(e, phi(n)) = gcd(${E}, ${phi}) = ${gcdE}`, note: "e is valid only when this GCD equals 1." },
        { title: "Find private exponent", value: `d = e inverse mod phi(n) = ${d}`, note: `Because ${E} * ${d} is congruent to 1 mod ${phi}.` },
        { title: "Encrypt", value: `c = m^e mod n = ${M}^${E} mod ${n} = ${cipher}`, note: "The ciphertext is computed using the public key." },
        { title: "Decrypt", value: `m = c^d mod n = ${cipher}^${d} mod ${n} = ${decrypted}`, note: "The plaintext is recovered using the private key." },
      ]
    : [];

  return (
    <Panel title="RSA Step-by-Step" subtitle="Generate small RSA keys, encrypt a message, then decrypt it back. Use small values for educational tracing.">
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Input label="Prime p" value={p} onChange={setP} />
        <Input label="Prime q" value={q} onChange={setQ} />
        <Input label="Public exponent e" value={e} onChange={setE} />
        <Input label="Message m" value={m} onChange={setM} />
      </div>
      {!canRun && <div className="mt-4 rounded-2xl bg-amber-500/10 p-4 text-amber-100">Make sure p and q are greater than 1, gcd(e, phi(n)) = 1, and message m is smaller than n.</div>}
      <div className="mt-5 grid gap-4 md:grid-cols-3">
        <ResultBox label="Public key" value={canRun ? `(${E}, ${n})` : "-"} />
        <ResultBox label="Private key" value={canRun ? `(${d}, ${n})` : "-"} />
        <ResultBox label="Ciphertext" value={cipher} />
      </div>
      {canRun && <div className="mt-5"><TraceList trace={trace} /></div>}
    </Panel>
  );
}

function DhTool() {
  const [p, setP] = useState("23");
  const [g, setG] = useState("5");
  const [a, setA] = useState("6");
  const [b, setB] = useState("15");
  const P = Number(p);
  const G = Number(g);
  const Asecret = Number(a);
  const Bsecret = Number(b);
  const valid = [P, G, Asecret, Bsecret].every((x) => Number.isInteger(x) && x > 0);
  const pubA = valid ? bigModPow(G, Asecret, P).result.toString() : "-";
  const pubB = valid ? bigModPow(G, Bsecret, P).result.toString() : "-";
  const sharedA = valid ? bigModPow(pubB, Asecret, P).result.toString() : "-";
  const sharedB = valid ? bigModPow(pubA, Bsecret, P).result.toString() : "-";
  const trace = valid
    ? [
        { title: "Public parameters", value: `p=${P}, g=${G}`, note: "p and g are known by both Alice and Bob." },
        { title: "Alice secret", value: `a=${Asecret}`, note: "Alice keeps this value private." },
        { title: "Bob secret", value: `b=${Bsecret}`, note: "Bob keeps this value private." },
        { title: "Alice public value", value: `A = g^a mod p = ${G}^${Asecret} mod ${P} = ${pubA}`, note: "Alice sends A to Bob." },
        { title: "Bob public value", value: `B = g^b mod p = ${G}^${Bsecret} mod ${P} = ${pubB}`, note: "Bob sends B to Alice." },
        { title: "Alice computes shared key", value: `s = B^a mod p = ${pubB}^${Asecret} mod ${P} = ${sharedA}`, note: "Alice uses Bob's public value with her secret." },
        { title: "Bob computes shared key", value: `s = A^b mod p = ${pubA}^${Bsecret} mod ${P} = ${sharedB}`, note: "Bob uses Alice's public value with his secret." },
      ]
    : [];
  return (
    <Panel title="Diffie-Hellman Key Exchange" subtitle="Watch Alice and Bob create the same shared key without sending the secret directly.">
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Input label="Prime modulus p" value={p} onChange={setP} />
        <Input label="Generator g" value={g} onChange={setG} />
        <Input label="Alice secret a" value={a} onChange={setA} />
        <Input label="Bob secret b" value={b} onChange={setB} />
      </div>
      <div className="mt-5 grid gap-4 md:grid-cols-4">
        <ResultBox label="Alice public A" value={pubA} />
        <ResultBox label="Bob public B" value={pubB} />
        <ResultBox label="Alice shared key" value={sharedA} />
        <ResultBox label="Bob shared key" value={sharedB} />
      </div>
      {valid && <div className="mt-5"><TraceList trace={trace} /></div>}
    </Panel>
  );
}

function ModularMathTool() {
  const [a, setA] = useState("240");
  const [b, setB] = useState("46");
  const [base, setBase] = useState("7");
  const [exp, setExp] = useState("560");
  const [mod, setMod] = useState("561");
  const A = Number(a);
  const B = Number(b);
  const M = Number(mod);
  const Base = Number(base);
  const Exp = Number(exp);
  const eg = Number.isInteger(A) && Number.isInteger(B) && B !== 0 ? egcdNumber(Math.abs(A), Math.abs(B)) : null;
  const inverse = Number.isInteger(A) && Number.isInteger(M) && M > 1 ? modInverseNumber(A, M) : null;
  const pow = Number.isInteger(Base) && Number.isInteger(Exp) && Number.isInteger(M) && Exp >= 0 && M > 0 ? bigModPow(Base, Exp, M) : null;

  return (
    <Panel title="Modular Math Lab" subtitle="This section supports RSA, Diffie-Hellman, ElGamal, signatures, and many exam calculations.">
      <div className="grid gap-5 xl:grid-cols-2">
        <div className="rounded-3xl border border-white/10 bg-slate-900/60 p-4">
          <h3 className="text-xl font-bold">GCD and Extended Euclidean Algorithm</h3>
          <div className="mt-4 grid gap-4 md:grid-cols-2">
            <Input label="a" value={a} onChange={setA} />
            <Input label="b" value={b} onChange={setB} />
          </div>
          {eg && (
            <>
              <div className="mt-4 grid gap-4 md:grid-cols-2">
                <ResultBox label="gcd(a,b)" value={eg.gcd} />
                <ResultBox label="Bezout identity" value={`${eg.x}(${Math.abs(A)}) + ${eg.y}(${Math.abs(B)}) = ${eg.gcd}`} />
              </div>
              <div className="mt-4 overflow-auto rounded-2xl border border-white/10">
                <table className="w-full min-w-[600px] text-left text-sm">
                  <thead className="bg-white/5 text-slate-300"><tr><th className="p-3">q</th><th className="p-3">old r</th><th className="p-3">r</th><th className="p-3">old s</th><th className="p-3">s</th><th className="p-3">old t</th><th className="p-3">t</th></tr></thead>
                  <tbody>{eg.rows.map((row, idx) => <tr key={idx} className="border-t border-white/10"><td className="p-3">{row.q}</td><td className="p-3">{row.oldR}</td><td className="p-3">{row.r}</td><td className="p-3">{row.oldS}</td><td className="p-3">{row.s}</td><td className="p-3">{row.oldT}</td><td className="p-3">{row.t}</td></tr>)}</tbody>
                </table>
              </div>
            </>
          )}
        </div>
        <div className="rounded-3xl border border-white/10 bg-slate-900/60 p-4">
          <h3 className="text-xl font-bold">Modular inverse and square-and-multiply</h3>
          <div className="mt-4 grid gap-4 md:grid-cols-3">
            <Input label="a" value={a} onChange={setA} />
            <Input label="modulus m" value={mod} onChange={setMod} />
            <div className="md:pt-6"><ResultBox label="a inverse mod m" value={inverse === null ? "No inverse" : inverse} /></div>
          </div>
          <div className="mt-6 grid gap-4 md:grid-cols-3">
            <Input label="base" value={base} onChange={setBase} />
            <Input label="exponent" value={exp} onChange={setExp} />
            <Input label="modulus" value={mod} onChange={setMod} />
          </div>
          {pow && (
            <>
              <div className="mt-4"><ResultBox label={`${base}^${exp} mod ${mod}`} value={pow.result.toString()} /></div>
              <div className="mt-4 space-y-2">
                {pow.steps.slice(0, 16).map((s, idx) => (
                  <div key={idx} className="rounded-xl bg-black/25 p-3 font-mono text-sm text-slate-200">
                    bit={s.bit}: result {s.before.toString()} {s.bit ? `* ${s.base.toString()}` : "unchanged"} to {s.after.toString()}
                  </div>
                ))}
                {pow.steps.length > 16 && <div className="text-sm text-slate-400">Only the first 16 multiplication steps are shown to keep the page readable.</div>}
              </div>
            </>
          )}
        </div>
      </div>
    </Panel>
  );
}

function CaesarTool() {
  const [text, setText] = useState("HELLO CRYPTO");
  const [shift, setShift] = useState("3");
  const [mode, setMode] = useState("encrypt");
  const { output, rows } = caesarTransform(text, shift, mode);
  return (
    <Panel title="Caesar Cipher" subtitle="A simple classical cipher where each letter is shifted by a fixed amount.">
      <div className="grid gap-4 md:grid-cols-3">
        <Input label="Text" value={text} onChange={setText} />
        <Input label="Shift key" value={shift} onChange={setShift} />
        <Select label="Mode" value={mode} onChange={setMode}><option value="encrypt">Encrypt</option><option value="decrypt">Decrypt</option></Select>
      </div>
      <div className="mt-5"><ResultBox label="Output" value={output} /></div>
      <div className="mt-5 overflow-auto rounded-2xl border border-white/10">
        <table className="w-full min-w-[520px] text-left text-sm">
          <thead className="bg-white/5"><tr><th className="p-3">Input</th><th className="p-3">Number</th><th className="p-3">Operation</th><th className="p-3">Output</th></tr></thead>
          <tbody>{rows.map((r, i) => <tr key={i} className="border-t border-white/10"><td className="p-3 font-mono">{r.input}</td><td className="p-3">{r.number}</td><td className="p-3 font-mono">{r.operation}</td><td className="p-3 font-mono text-cyan-200">{r.output}</td></tr>)}</tbody>
        </table>
      </div>
    </Panel>
  );
}

function ColumnarTool() {
  const [text, setText] = useState("WE ARE DISCOVERED FLEE AT ONCE");
  const [key, setKey] = useState("5 2 1 4 3");
  const [mode, setMode] = useState("encrypt");
  const result = mode === "encrypt" ? columnarEncrypt(text, key) : columnarDecrypt(text, key);
  const orderByIndex = result.order.reduce((acc, item) => ({ ...acc, [item.idx]: item.rank }), {});
  return (
    <Panel title="Columnar Transposition" subtitle="Fill the message into a table, then read columns based on a numeric key order. Example: 3 1 4 2 means read column 2 first, column 1 second, column 4 third, and column 3 fourth.">
      <div className="grid gap-4 md:grid-cols-3">
        <Input label={mode === "encrypt" ? "Plaintext" : "Ciphertext"} value={text} onChange={setText} />
        <Input label="Numeric key order" value={key} onChange={setKey} placeholder="3 1 4 2" />
        <Select label="Mode" value={mode} onChange={setMode}><option value="encrypt">Encrypt</option><option value="decrypt">Decrypt</option></Select>
      </div>
      {result.error && <div className="mt-4 rounded-2xl bg-rose-500/10 p-4 text-rose-200">{result.error}</div>}
      <div className="mt-5"><ResultBox label="Output" value={result.output || "-"} /></div>
      {result.grid.length > 0 && (
        <div className="mt-5 overflow-auto rounded-2xl border border-white/10 p-3">
          <table className="mx-auto border-separate border-spacing-2 text-center font-mono">
            <thead>
              <tr>{result.numbers.map((num, idx) => <th key={idx} className="rounded-xl bg-cyan-300/20 px-4 py-2 text-cyan-100">{num}<br /><span className="text-xs text-slate-300">read order {orderByIndex[idx]}</span></th>)}</tr>
            </thead>
            <tbody>{result.grid.map((row, r) => <tr key={r}>{row.map((cell, c) => <td key={c} className="rounded-xl bg-slate-800 px-4 py-3 text-lg">{cell}</td>)}</tr>)}</tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function HashTool() {
  const [a, setA] = useState("Cryptography is fun");
  const [b, setB] = useState("Cryptography is fan");
  const [ha, setHa] = useState("");
  const [hb, setHb] = useState("");
  useEffect(() => {
    let alive = true;
    Promise.all([sha256Hex(a), sha256Hex(b)]).then(([x, y]) => {
      if (alive) {
        setHa(x);
        setHb(y);
      }
    });
    return () => { alive = false; };
  }, [a, b]);
  const dist = hammingDistance(ha, hb);
  const percent = ha && hb ? ((dist / 256) * 100).toFixed(2) : "0.00";
  return (
    <Panel title="Hash Avalanche Demo" subtitle="Change one character and notice how the SHA-256 hash changes heavily. This is called the avalanche effect.">
      <div className="grid gap-4 lg:grid-cols-2">
        <Input label="Message A" value={a} onChange={setA} />
        <Input label="Message B" value={b} onChange={setB} />
      </div>
      <div className="mt-5 grid gap-4 lg:grid-cols-2">
        <div className="rounded-2xl border border-white/10 bg-slate-900/70 p-4"><div className="text-sm text-slate-400">SHA-256(A)</div><div className="mt-2 break-all font-mono text-cyan-200">{ha}</div></div>
        <div className="rounded-2xl border border-white/10 bg-slate-900/70 p-4"><div className="text-sm text-slate-400">SHA-256(B)</div><div className="mt-2 break-all font-mono text-cyan-200">{hb}</div></div>
      </div>
      <div className="mt-5 grid gap-4 md:grid-cols-2">
        <ResultBox label="Different bits" value={`${dist} / 256`} />
        <ResultBox label="Change percentage" value={`${percent}%`} />
      </div>
    </Panel>
  );
}

function TlsTool() {
  const [mode, setMode] = useState("tcp");
  const [step, setStep] = useState(0);
  const [message, setMessage] = useState("hello encrypted");
  const [clientName, setClientName] = useState("Client A");
  const [serverName, setServerName] = useState("Client B / Server");
  const [domain, setDomain] = useState("cryptolab.local");
  const [organization, setOrganization] = useState("CryptoLab Server");
  const [caName, setCaName] = useState("CryptoLab Certificate Authority");
  const [trustedCa, setTrustedCa] = useState(true);
  const [fakeCert, setFakeCert] = useState(false);

  function simpleHash(text) {
    let h = 2166136261;
    for (let i = 0; i < text.length; i++) {
      h ^= text.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return (h >>> 0).toString(16).padStart(8, "0").toUpperCase();
  }

  function pseudoEncrypt(text, key) {
    if (!text) return "00";
    const safeKey = key || "session-key";
    return text
      .split("")
      .map((ch, i) => (ch.charCodeAt(0) ^ safeKey.charCodeAt(i % safeKey.length)).toString(16).padStart(2, "0"))
      .join(" ")
      .toUpperCase();
  }

  const sessionKey = `SK-${simpleHash(`${domain}|${clientName}|${serverName}`).slice(0, 6)}`;
  const encryptedPayload = pseudoEncrypt(message, sessionKey);
  const certSerial = simpleHash(`${domain}|${organization}|${caName}`).slice(0, 10);
  const publicKey = `PUB-${simpleHash(`${domain}-public`).slice(0, 10)}`;
  const privateKey = `PRV-${simpleHash(`${domain}-private`).slice(0, 10)}`;
  const csr = `CSR-${simpleHash(`${domain}|${organization}|${publicKey}`).slice(0, 10)}`;
  const fingerprint = simpleHash(`${certSerial}|${domain}|${caName}|${publicKey}`);
  const certStatus = fakeCert ? "Danger: fake certificate" : trustedCa ? "Trusted certificate" : "Warning: unknown CA";
  const certStatusClass = fakeCert ? "bg-rose-500/15 text-rose-100 border-rose-300/20" : trustedCa ? "bg-emerald-500/15 text-emerald-100 border-emerald-300/20" : "bg-amber-500/15 text-amber-100 border-amber-300/20";

  const tcpSteps = [
    {
      title: "Application prepares message",
      actor: clientName,
      packet: message || "empty message",
      visible: message || "empty message",
      note: "The user message is prepared before any security is added.",
      active: "client",
    },
    {
      title: "TCP SYN",
      actor: `${clientName} to ${serverName}`,
      packet: "SYN",
      visible: "Connection request only",
      note: "The client asks to open a TCP connection.",
      active: "path",
    },
    {
      title: "TCP SYN-ACK",
      actor: `${serverName} to ${clientName}`,
      packet: "SYN-ACK",
      visible: "Connection accepted",
      note: "The server replies and accepts the connection.",
      active: "server",
    },
    {
      title: "TCP ACK",
      actor: `${clientName} to ${serverName}`,
      packet: "ACK",
      visible: "Handshake complete",
      note: "The TCP channel is ready, but it is not encrypted.",
      active: "path",
    },
    {
      title: "Send application data",
      actor: `${clientName} to ${serverName}`,
      packet: message || "empty message",
      visible: message || "empty message",
      note: "In plain TCP, the packet payload is readable by anyone capturing traffic.",
      active: "attacker",
    },
    {
      title: "Server receives plaintext",
      actor: serverName,
      packet: message || "empty message",
      visible: message || "empty message",
      note: "The server receives the exact message, but privacy was not protected during transmission.",
      active: "server",
    },
  ];

  const tlsSteps = [
    {
      title: "TCP connection first",
      actor: `${clientName} and ${serverName}`,
      packet: "SYN to SYN-ACK to ACK",
      visible: "Only TCP setup packets",
      note: "TLS runs on top of TCP. First, a normal TCP connection is created.",
      active: "path",
    },
    {
      title: "ClientHello",
      actor: `${clientName} to ${serverName}`,
      packet: "Supported TLS versions + cipher suites + client random",
      visible: "Handshake metadata, not the secret message",
      note: "The client starts TLS and tells the server what security options it supports.",
      active: "client",
    },
    {
      title: "ServerHello",
      actor: `${serverName} to ${clientName}`,
      packet: "Chosen cipher suite + server random",
      visible: "Handshake metadata, not the secret message",
      note: "The server chooses the TLS settings that both sides will use.",
      active: "server",
    },
    {
      title: "Certificate sent",
      actor: `${serverName} to ${clientName}`,
      packet: `Certificate for ${domain}`,
      visible: `Domain=${domain}, Issuer=${fakeCert ? "Fake Evil CA" : caName}`,
      note: "The certificate proves the server identity using a public key and CA signature.",
      active: "cert",
    },
    {
      title: "Certificate validation",
      actor: clientName,
      packet: certStatus,
      visible: certStatus,
      note: fakeCert ? "The browser should reject this certificate because the identity cannot be trusted." : trustedCa ? "The certificate is accepted because the CA is trusted and the domain matches." : "The browser warns the user because the issuer is not trusted.",
      active: fakeCert || !trustedCa ? "attacker" : "client",
    },
    {
      title: "Key exchange",
      actor: `${clientName} and ${serverName}`,
      packet: "Shared secret is created",
      visible: "Observer sees exchange messages, not the final secret",
      note: "Both sides derive the same secret without sending the final session key directly.",
      active: "path",
    },
    {
      title: "Session keys derived",
      actor: "Both sides",
      packet: sessionKey,
      visible: "Not visible to attacker",
      note: "The session key is used only for this secure conversation.",
      active: "lock",
    },
    {
      title: "Encrypted application data",
      actor: `${clientName} to ${serverName}`,
      packet: encryptedPayload,
      visible: encryptedPayload,
      note: "Now the original message is encrypted before being sent over the network.",
      active: "lock",
    },
    {
      title: "Server decrypts message",
      actor: serverName,
      packet: message || "empty message",
      visible: "Only the server can recover the plaintext",
      note: "The receiver uses the session key to decrypt the packet and read the original message.",
      active: "server",
    },
  ];

  const certSteps = [
    {
      title: "Generate key pair",
      actor: serverName,
      packet: `${publicKey} / ${privateKey}`,
      visible: "Public key can be shared; private key must stay secret",
      note: "The server creates a public/private key pair. The private key should never leave the server.",
      active: "server",
    },
    {
      title: "Create CSR",
      actor: serverName,
      packet: csr,
      visible: `Domain=${domain}, Organization=${organization}, PublicKey=${publicKey}`,
      note: "CSR means Certificate Signing Request. It asks a CA to issue a certificate for this domain.",
      active: "cert",
    },
    {
      title: "CA verifies identity",
      actor: fakeCert ? "Fake attacker" : caName,
      packet: fakeCert ? "Identity not truly verified" : "Domain ownership checked",
      visible: fakeCert ? "Suspicious issuer" : "CA validation process",
      note: fakeCert ? "A fake certificate may look similar, but it will not be trusted by the browser." : "A real CA checks that the requester controls the domain before signing.",
      active: fakeCert ? "attacker" : "cert",
    },
    {
      title: "Certificate issued",
      actor: fakeCert ? "Fake Evil CA" : caName,
      packet: `Serial=${certSerial}`,
      visible: `Issuer=${fakeCert ? "Fake Evil CA" : caName}, Fingerprint=${fingerprint}`,
      note: "The certificate binds the domain name to the server public key.",
      active: "cert",
    },
    {
      title: "Browser trust decision",
      actor: clientName,
      packet: certStatus,
      visible: certStatus,
      note: fakeCert ? "The browser should block or warn because the certificate chain is suspicious." : trustedCa ? "The browser accepts the certificate and continues the TLS handshake." : "The browser warns because the CA is not in the trusted root store.",
      active: fakeCert || !trustedCa ? "attacker" : "client",
    },
  ];

  const currentSteps = mode === "tcp" ? tcpSteps : mode === "tls" ? tlsSteps : certSteps;
  const current = currentSteps[Math.min(step, currentSteps.length - 1)];

  function changeMode(nextMode) {
    setMode(nextMode);
    setStep(0);
  }

  function nextStep() {
    setStep((s) => Math.min(s + 1, currentSteps.length - 1));
  }

  function prevStep() {
    setStep((s) => Math.max(s - 1, 0));
  }

  function resetStep() {
    setStep(0);
  }

  function NodeCard({ id, title, icon, subtitle }) {
    const active = current.active === id;
    return (
      <div className={`rounded-3xl border p-4 text-center transition ${active ? "scale-[1.03] border-cyan-300 bg-cyan-300/15 shadow-xl shadow-cyan-400/10" : "border-white/10 bg-slate-900/70"}`}>
        <div className="text-4xl">{icon}</div>
        <div className="mt-2 font-bold">{title}</div>
        <div className="mt-1 text-xs text-slate-400">{subtitle}</div>
      </div>
    );
  }

  return (
    <Panel title="TCP vs TLS Interactive Lab" subtitle="Type a message, send it using plain TCP, then send the same message using TLS and compare what an attacker can see.">
      <div className="grid gap-4 xl:grid-cols-[1fr_360px]">
        <div className="rounded-3xl border border-white/10 bg-slate-900/60 p-5">
          <div className="grid gap-4 md:grid-cols-3">
            <Input label="Sender" value={clientName} onChange={setClientName} />
            <Input label="Receiver" value={serverName} onChange={setServerName} />
            <Input label="Message to send" value={message} onChange={setMessage} placeholder="Type your message here" />
          </div>

          <div className="mt-5 flex flex-wrap gap-2">
            <button onClick={() => changeMode("tcp")} className={`rounded-full px-4 py-2 text-sm font-semibold transition ${mode === "tcp" ? "bg-rose-300 text-slate-950" : "bg-white/10 hover:bg-white/15"}`}>Plain TCP</button>
            <button onClick={() => changeMode("tls")} className={`rounded-full px-4 py-2 text-sm font-semibold transition ${mode === "tls" ? "bg-emerald-300 text-slate-950" : "bg-white/10 hover:bg-white/15"}`}>TLS Protected</button>
            <button onClick={() => changeMode("cert")} className={`rounded-full px-4 py-2 text-sm font-semibold transition ${mode === "cert" ? "bg-cyan-300 text-slate-950" : "bg-white/10 hover:bg-white/15"}`}>Certificate Lab</button>
          </div>

          <div className="mt-6 rounded-3xl border border-white/10 bg-gradient-to-br from-slate-950 to-slate-900 p-5">
            <div className="grid items-center gap-3 md:grid-cols-[1fr_80px_1fr_80px_1fr]">
              <NodeCard id="client" icon="💻" title={clientName} subtitle="sender" />
              <div className={`hidden text-center text-3xl md:block ${current.active === "path" || current.active === "lock" ? "text-cyan-200" : "text-slate-600"}`}>→</div>
              <NodeCard id="attacker" icon="🕵️" title="Network Observer" subtitle="Wireshark / attacker view" />
              <div className={`hidden text-center text-3xl md:block ${current.active === "path" || current.active === "lock" ? "text-cyan-200" : "text-slate-600"}`}>→</div>
              <NodeCard id="server" icon="🖥️" title={serverName} subtitle="receiver" />
            </div>

            <div className="mt-5 grid gap-4 lg:grid-cols-3">
              <div className="rounded-2xl border border-white/10 bg-black/25 p-4">
                <div className="text-xs uppercase tracking-wider text-slate-400">Current step</div>
                <div className="mt-1 text-xl font-bold text-cyan-100">{step + 1}. {current.title}</div>
                <div className="mt-2 text-sm text-slate-300">{current.actor}</div>
              </div>
              <div className="rounded-2xl border border-white/10 bg-black/25 p-4">
                <div className="text-xs uppercase tracking-wider text-slate-400">Packet travelling now</div>
                <div className="mt-1 break-all font-mono text-sm text-cyan-200">{current.packet}</div>
              </div>
              <div className="rounded-2xl border border-white/10 bg-black/25 p-4">
                <div className="text-xs uppercase tracking-wider text-slate-400">Observer can see</div>
                <div className={`mt-1 break-all font-mono text-sm ${mode === "tcp" && step >= 4 ? "text-rose-200" : "text-emerald-200"}`}>{current.visible}</div>
              </div>
            </div>

            <div className="mt-4 rounded-2xl bg-white/5 p-4 text-slate-300">{current.note}</div>

            <div className="mt-5 flex flex-wrap items-center justify-between gap-3">
              <div className="flex gap-2">
                <button onClick={prevStep} className="rounded-2xl bg-white/10 px-4 py-2 text-sm font-semibold hover:bg-white/15">Previous</button>
                <button onClick={nextStep} className="rounded-2xl bg-cyan-300 px-4 py-2 text-sm font-bold text-slate-950 hover:bg-cyan-200">Next step</button>
                <button onClick={resetStep} className="rounded-2xl bg-white/10 px-4 py-2 text-sm font-semibold hover:bg-white/15">Reset</button>
              </div>
              <div className="text-sm text-slate-400">Step {step + 1} of {currentSteps.length}</div>
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <div className="rounded-3xl border border-white/10 bg-slate-900/60 p-5">
            <h3 className="text-xl font-bold">Live security comparison</h3>
            <div className="mt-4 space-y-3">
              <div className="rounded-2xl bg-rose-500/10 p-4">
                <div className="font-semibold text-rose-100">Plain TCP capture</div>
                <div className="mt-2 break-all rounded-xl bg-black/30 p-3 font-mono text-sm text-rose-200">{message || "empty message"}</div>
                <p className="mt-2 text-sm text-slate-300">The message itself is visible in the packet payload.</p>
              </div>
              <div className="rounded-2xl bg-emerald-500/10 p-4">
                <div className="font-semibold text-emerald-100">TLS packet capture</div>
                <div className="mt-2 break-all rounded-xl bg-black/30 p-3 font-mono text-sm text-emerald-200">{encryptedPayload}</div>
                <p className="mt-2 text-sm text-slate-300">The observer sees encrypted bytes, not the original message.</p>
              </div>
              <div className="rounded-2xl bg-cyan-500/10 p-4">
                <div className="font-semibold text-cyan-100">Session key idea</div>
                <div className="mt-2 rounded-xl bg-black/30 p-3 font-mono text-sm text-cyan-200">{sessionKey}</div>
                <p className="mt-2 text-sm text-slate-300">This is a simplified visual key, not a real TLS key.</p>
              </div>
            </div>
          </div>

          <div className="rounded-3xl border border-white/10 bg-slate-900/60 p-5">
            <h3 className="text-xl font-bold">Certificate simulation</h3>
            <div className="mt-4 space-y-3">
              <Input label="Domain name" value={domain} onChange={setDomain} />
              <Input label="Organization" value={organization} onChange={setOrganization} />
              <Input label="Certificate Authority" value={caName} onChange={setCaName} />
              <div className="grid grid-cols-2 gap-2">
                <button onClick={() => setTrustedCa((v) => !v)} className={`rounded-2xl px-3 py-2 text-sm font-semibold ${trustedCa ? "bg-emerald-300 text-slate-950" : "bg-amber-300 text-slate-950"}`}>{trustedCa ? "Trusted CA" : "Unknown CA"}</button>
                <button onClick={() => setFakeCert((v) => !v)} className={`rounded-2xl px-3 py-2 text-sm font-semibold ${fakeCert ? "bg-rose-300 text-slate-950" : "bg-white/10 text-slate-100"}`}>{fakeCert ? "Fake Cert ON" : "Fake Cert OFF"}</button>
              </div>
              <div className={`rounded-2xl border p-4 ${certStatusClass}`}>
                <div className="font-bold">{certStatus}</div>
                <div className="mt-2 space-y-1 font-mono text-xs">
                  <div>Subject: {fakeCert ? "evil.example" : domain}</div>
                  <div>Issuer: {fakeCert ? "Fake Evil CA" : caName}</div>
                  <div>Serial: {certSerial}</div>
                  <div>Public Key: {publicKey}</div>
                  <div>Fingerprint: {fingerprint}</div>
                </div>
              </div>
              <div className="rounded-2xl bg-white/5 p-4 text-sm text-slate-300">
                Certificate creation flow: server creates keys, creates CSR, CA verifies domain, CA signs certificate, browser checks trust.
              </div>
            </div>
          </div>
        </div>
      </div>
    </Panel>
  );
}

export default function CryptoLabApp() {
  const [active, setActive] = useState("sdes");
  const currentTitle = useMemo(() => tools.find((t) => t.id === active)?.title || "CryptoLab", [active]);
  useEffect(() => {
    document.title = currentTitle;
  }, [currentTitle]);

  return (
    <Shell active={active} setActive={setActive}>
      {active === "sdes" && <SdesTool />}
      {active === "rsa" && <RsaTool />}
      {active === "dh" && <DhTool />}
      {active === "mod" && <ModularMathTool />}
      {active === "caesar" && <CaesarTool />}
      {active === "columnar" && <ColumnarTool />}
      {active === "hash" && <HashTool />}
      {active === "tls" && <TlsTool />}
    </Shell>
  );
}
