/** Exercise routing against the installed Harness ToolRuntime, without a model. */
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { test } from 'node:test';
import * as policy from '../integrations/deepseek-harness/ctf-route-guard.mjs';

const base=process.env.CTF_HARNESS_PACKAGE_JSON ?? String.raw`D:\deepseek-harness\DSH Desktop\resources\app\package.json`;
const req=createRequire(base);
const load=async name=>import(pathToFileURL(req.resolve(name)).href);
const {Context}=await load('@deepseek-ai/cordis');
const {default:SystemPrompt}=await load('@deepseek-ai/dsh-system-prompt');
const {default:ToolRuntime,defineTool}=await load('@deepseek-ai/dsh-tools');
const {createScope}=await load('@deepseek-ai/dsh-scope');

async function setup(mode='after_ctf_intake') {
  const ctx=new Context();
  await ctx.plugin(SystemPrompt);
  await ctx.plugin(ToolRuntime);
  const calls=[];
  for(const name of ['pwsh','write','mcp__ctf_system__ctf_start','mcp__ctf_system__ctf_call','mcp__ctf_system__ctf_tools']) {
    ctx.tools.register(defineTool({name,description:'Fixture',parameters:{},
      output:{schema:{type:'string'},render:(_,value)=>[{type:'text',text:value}]},
      async execute(){calls.push(name);return 'executed';}}));
  }
  await ctx.plugin(policy,{mode});
  let sequence=0;
  const run=(name,agent)=>ctx.tools.execute({name,arguments:{},agent,
    callId:'guard-'+(++sequence),signal:AbortSignal.timeout(1000)});
  return {ctx,calls,run};
}

test('always mode blocks native execution before its body runs',async()=>{
  const {run,calls}=await setup('always');
  const result=await run('pwsh');
  assert.equal(result.isError,true);
  assert.match(result.content[0].text,/CTF_SYSTEM_ROUTE_REQUIRED/);
  assert.deepEqual(calls,[]);
});

test('CTF intake blocks later native execution while keeping system calls',async()=>{
  const {run,calls}=await setup();
  assert.equal((await run('pwsh')).isError,false);
  assert.equal((await run('mcp__ctf_system__ctf_start')).isError,false);
  assert.equal((await run('write')).isError,true);
  assert.equal((await run('mcp__ctf_system__ctf_call')).isError,false);
  assert.deepEqual(calls,['pwsh','mcp__ctf_system__ctf_start','mcp__ctf_system__ctf_call']);
});

test('later permission allow listeners cannot bypass the route guard',async()=>{
  const {ctx,run,calls}=await setup('always');
  ctx.on('tools/pre-execute',()=>Promise.resolve({kind:'allow'}));
  assert.equal((await run('pwsh')).isError,true);
  assert.deepEqual(calls,[]);
});

test('route activation is isolated between agent sessions',async()=>{
  const {ctx,run}=await setup();
  const a={id:'agent-a'},b={id:'agent-b'};
  await ctx.plugin(Object.assign(inner=>{createScope(inner,a);},{inject:['tools','systemPrompt']}));
  await ctx.plugin(Object.assign(inner=>{createScope(inner,b);},{inject:['tools','systemPrompt']}));
  assert.equal((await run('mcp__ctf_system__ctf_start',a)).isError,false);
  assert.equal((await run('pwsh',a)).isError,true);
  assert.equal((await run('pwsh',b)).isError,false);
});

test('only exact public names are accepted',()=>{
  const guard=policy.createGuard('always');
  assert.equal(guard({name:'mcp__ctf-system__ctf_call'}),undefined);
  assert.match(guard({name:'mcp__ctf_system__pwsh'}),/CTF_SYSTEM_ROUTE_REQUIRED/);
  assert.throws(()=>policy.createGuard('unknown'),/Unknown/);
});
