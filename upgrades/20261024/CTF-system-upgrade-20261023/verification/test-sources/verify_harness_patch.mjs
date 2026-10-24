/** Load the installed patch via its generated YAML entry using real Harness services. */
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

const [profile, originalProfile, output] = process.argv.slice(2);
const req = createRequire(process.env.CTF_HARNESS_PACKAGE_JSON ?? String.raw`D:\deepseek-harness\DSH Desktop\resources\app\package.json`);
const yaml = req('yaml');
const checks = [];
const check = (name, condition) => { checks.push({name,passed:Boolean(condition)}); assert.ok(condition,name); };
const options = {customTags:[{tag:'tag:yaml.org,2002:js',resolve:value=>({__jsExpr:value})}]};
const entries = yaml.parse(await readFile(profile,'utf8'),options);
check('generated_patch_is_valid_yaml',Array.isArray(entries));
check('existing_profile_remains_parseable',Array.isArray(yaml.parse(await readFile(originalProfile,'utf8'),options)));
const entry = entries.flatMap(e=>e.insert??[]).find(e=>e.id==='ctf-system-shared-workflow');
check('configured_route_mode_is_after_intake',entry?.config?.mode==='after_ctf_intake');
const load = async name=>import(pathToFileURL(req.resolve(name)).href);
const {Context} = await load('@deepseek-ai/cordis');
const {default:SystemPrompt} = await load('@deepseek-ai/dsh-system-prompt');
const {default:ToolRuntime,defineTool} = await load('@deepseek-ai/dsh-tools');
const ctx = new Context();
await ctx.plugin(SystemPrompt);
await ctx.plugin(ToolRuntime);
const calls=[];
for (const name of ['pwsh','mcp__ctf_system__ctf_start','mcp__ctf_system__ctf_call']) {
  ctx.tools.register(defineTool({name,description:'Self-built integration fixture',parameters:{},
    output:{schema:{type:'string'},render:(_,value)=>[{type:'text',text:value}]},
    async execute(){calls.push(name);return 'executed';}}));
}
await ctx.plugin(await import(entry.name),entry.config);
let id=0;
const run=name=>ctx.tools.execute({name,arguments:{},callId:'installed-'+(++id),signal:AbortSignal.timeout(1500)});
check('installed_plugin_allows_ctf_intake',(await run('mcp__ctf_system__ctf_start')).isError===false);
check('installed_plugin_blocks_native_body',(await run('pwsh')).isError===true && !calls.includes('pwsh'));
check('installed_plugin_keeps_system_calls',(await run('mcp__ctf_system__ctf_call')).isError===false);
const report={passed:true,checks,scope:'Generated YAML entry and installed file URL, actual Harness ToolRuntime; fixture tool bodies and no live model call.'};
await writeFile(output,JSON.stringify(report,null,2)+'\n','utf8');
console.log(JSON.stringify(report));
