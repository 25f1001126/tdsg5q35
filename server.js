const http = require('http');

function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value !== null && typeof value === 'object') {
    const out = {};
    const keys = Object.keys(value).filter((k) => k !== 'trace_id').sort();
    for (const k of keys) out[k] = canonicalize(value[k]);
    return out;
  }
  if (typeof value === 'string') {
    return value.trim().replace(/\s+/g, ' ');
  }
  return value;
}

function canonicalStr(step) {
  return JSON.stringify({ tool: step.tool, args: canonicalize(step.args || {}) });
}

function checkRepeat(steps) {
  if (steps.length < 3) return false;
  const last = canonicalStr(steps[steps.length - 1]);
  let count = 1;
  for (let i = steps.length - 2; i >= 0; i--) {
    if (canonicalStr(steps[i]) === last) count++;
    else break;
  }
  return count >= 3;
}

function checkCycle(steps) {
  if (steps.length < 6) return false;
  const c = steps.slice(-6).map(canonicalStr);
  const [a1, b1, a2, b2, a3, b3] = c;
  if (a1 === a2 && a2 === a3 && b1 === b2 && b2 === b3 && a1 !== b1) {
    return true;
  }
  return false;
}

function handleDecision(body) {
  const budget = body.budget_tokens;
  const steps = Array.isArray(body.steps) ? body.steps : [];

  if (steps.length === 0) {
    return { decision: 'continue', reason: 'Fresh run with no steps taken yet.' };
  }

  const total = steps.reduce((sum, s) => sum + (Number(s.tokens_used) || 0), 0);

  if (checkRepeat(steps)) {
    return { decision: 'halt', reason: 'Same tool called 3+ times in a row with functionally identical arguments (a loop).' };
  }
  if (checkCycle(steps)) {
    return { decision: 'halt', reason: 'Trailing steps show a repeating 2-step A/B cycle (a loop).' };
  }
  if (total >= budget) {
    return { decision: 'halt', reason: `Cumulative tokens_used (${total}) has reached the budget (${budget}).` };
  }
  return { decision: 'continue', reason: `Under budget (${total}/${budget}) with no loop detected.` };
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
    return;
  }
  if (req.method !== 'POST') {
    res.writeHead(405);
    res.end();
    return;
  }
  let data = '';
  req.on('data', (chunk) => { data += chunk; });
  req.on('end', () => {
    let result;
    try {
      const body = JSON.parse(data);
      result = handleDecision(body);
    } catch (e) {
      result = { decision: 'halt', reason: 'Malformed request body.' };
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(result));
  });
});

const port = process.env.PORT || 10000;
server.listen(port, () => console.log(`Run-guard listening on ${port}`));
