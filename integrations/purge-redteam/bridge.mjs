import fs from 'node:fs';
import path from 'node:path';
import { RedteamStore, dispatchAsync } from './upstream/lib/redteam/store-core.js';

const args = process.argv.slice(2);
if (args[0] !== '--data-dir' || !args[1] || args.length !== 2) throw Error('Explicit adapter data directory is required');
const root = path.resolve(args[1]);
const parts = [];
for await (const chunk of process.stdin) {
  parts.push(chunk);
}
const req = JSON.parse(Buffer.concat(parts).toString('utf8'));
if (!/^ctf-[a-f0-9]{16}$/.test(req.case || '')) throw Error('INVALID_CTF_CASE');
const allowed = new Set(['snapshot','assets','asset','graph','attackGraph','stats','vulns','vulnStats','credentials','access','sessions','webshells','tunnels','domains','web','httpEvidence','chain','scores','scoreChain','scoreReport','activeTests','testStats','consoleDigest','stages','reportTargets','discoveryTimeline','pocSearch','pocList','pocGet','pocStats','assetAdd','assetLink','addVuln','updateVuln','addCredential','addAccess','addWebshell','updateWebshell','addTunnel','updateTunnel','addHttpEvidence','addChainStep','assetTest','assessAsset','saveScorePoint','addScoreHit','saveStage','pocSave','pocUpdate','pocUse','report','prompts','shots','shotData','attackFiles','readAttackFile','templateSearch','templateStats','platformConfigGet','pocDelete','shotAdd','shotDelete','addAttackFile','import','savePrompt','resetPrompts','deleteScorePoint','platformConfigSave','platformAssignToolkit','probeSessions']);
if (!allowed.has(req.op)) throw Error('UNSUPPORTED_OPERATION');
function noLinks(target) {
  for (let current = path.resolve(target);; current = path.dirname(current)) {
    try { if (fs.lstatSync(current).isSymbolicLink()) throw Error('LINKED_STORAGE_PATH'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (path.dirname(current) === current) break;
  }
}
noLinks(root);
// Original roles, template lookup, validation and cross-engagement POC reuse
// remain upstream implementations. CTF owns task routing and command execution.
const store = new RedteamStore(root);
try {
  const engagement = store.openEngagement(req.case, [], { bindCurrent:false });
  let data = req.data || {};
  if (typeof data !== 'object' || Array.isArray(data)) throw Error('INVALID_DATA');
  if (req.provenance?.source_step != null) {
    if (req.provenance.wp_case !== req.case) throw Error('CASE_MISMATCH');
    const evidence = `CTF WP step ${req.provenance.source_step}; tool=${req.provenance.source_tool}`;
    data = { ...data, evidence: data.evidence ? `${data.evidence}\n${evidence}` : evidence };
  }
  let result;
  if (req.op === 'assetAdd') {
    if (!['passive','active'].includes(data.provenance) || typeof data.tool !== 'string') throw Error('Asset source provenance and tool are required');
    result = {ok:true, ...store.importBundle(engagement.id, {assets:[data]})};
  } else if (req.op === 'assetLink') {
    result = {ok:true, ...store.importBundle(engagement.id, {edges:[data]})};
  } else if (req.op === 'pocSave') {
    result = await dispatchAsync(store, {op:req.op,poc:{...(data.poc || data),engagement_id:engagement.id,engagement_name:req.case}});
  } else {
    // For POC lookup an explicit engagement is a provenance filter; other
    // operations always address the owning CTF engagement.
    result = await dispatchAsync(store, { ...data, op:req.op, ...(req.op.startsWith('poc') ? {} : {engagement:engagement.id}) });
  }
  if (req.provenance && result.ok) {
    fs.appendFileSync(path.join(root,'ctf-provenance.jsonl'), JSON.stringify({case:req.case,op:req.op,source:req.provenance,at:new Date().toISOString()})+'\n', {mode:0o600});
  }
  process.stdout.write(JSON.stringify(result)+'\n');
} finally { store.close(); }
