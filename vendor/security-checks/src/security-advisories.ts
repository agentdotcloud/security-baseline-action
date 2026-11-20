// DFINT-19–21/25: exact package-aware evidence, no prose/CPE matching.
import { z } from 'zod';
import semver from 'semver';
import { digest, screenedJson } from './security-primitives.ts';
// DFBASE-3: the injected public client and the occurrence it checks. Control's fixed-origin client (security-public-http.ts)
// and the baseline worker's host-mediated client both satisfy PublicHTTP; this package opens no connection of its own.
export interface PublicResponse {body:unknown;sha256:string;retrieved_at:string}
export interface PublicHTTP {json(url:string,body?:unknown,max?:number):Promise<PublicResponse>}
export interface InventoryOccurrence {entry:string;name:string;version:string;resolved:string;integrity:string;dev:boolean;optional:boolean}
export const OsvId=z.string().min(1).max(200).regex(/^[A-Za-z0-9][A-Za-z0-9_.:-]*$/);
const Package=z.object({ecosystem:z.string().max(100),name:z.string().max(214)}).passthrough();
export const OsvRecord=z.object({id:OsvId,modified:z.iso.datetime({offset:true}),aliases:z.array(z.string().max(200)).max(100).optional(),withdrawn:z.iso.datetime({offset:true}).optional(),summary:z.string().max(12000).optional(),affected:z.array(z.object({package:Package,versions:z.array(z.string().max(256)).max(100000).optional(),ranges:z.array(z.object({type:z.string().max(100),events:z.array(z.record(z.string(),z.string().max(256))).max(10000)}).passthrough()).max(1000).optional()}).passthrough()).max(10000)}).passthrough();
export type Advisory=z.infer<typeof OsvRecord>;
export function osvMatch(raw:unknown,name:string,version:string):{state:'affected'|'not-affected'|'held';reason:string;affected_digest:string|null;flaw_ref:string|null}{
 const parsed=OsvRecord.safeParse(raw);if(!parsed.success||!semver.valid(version))return {state:'held',reason:'unsupported_advisory_or_version',affected_digest:null,flaw_ref:null};
 const r=parsed.data,entries=r.affected.filter(a=>a.package.ecosystem==='npm'&&a.package.name===name),refs=[r.id,...r.aliases??[]].filter(s=>/^GHSA-[a-z0-9-]+$/.test(s));
 const base={affected_digest:digest(entries),flaw_ref:new Set(refs).size===1?`github-advisory:${refs[0]}`:null};
 if(r.withdrawn)return {...base,state:'held',reason:'withdrawn_source'};
 if(!entries.length)return {...base,state:'held',reason:'package_identity_unmatched'};
 let match=false;
 try{
  for(const a of entries){
   if(a.versions){for(const v of a.versions){if(!semver.valid(v))throw Error('unsupported_advisory_version');if(semver.eq(v,version))match=true;}}
   for(const range of a.ranges??[]){
    if(range.type!=='SEMVER')throw Error('unsupported_advisory_range');let lower:string|null=null,open=false,prior:string|null=null;
    for(const event of range.events){const keys=Object.keys(event);if(keys.length!==1)throw Error('malformed_range');const key=keys[0]!,v=event[key]!;
     if(!['introduced','fixed','last_affected','limit'].includes(key)||!(key==='introduced'&&v==='0')&&!semver.valid(v))throw Error('unsupported_advisory_range');
     if(prior&&v!=='0'&&semver.lt(v,prior))throw Error('unordered_range');
     if(key==='introduced'){if(open)throw Error('malformed_range');lower=v==='0'?null:v;open=true;}
     else{if(!open)throw Error('malformed_range');if((!lower||semver.gte(version,lower))&&(key==='last_affected'?semver.lte(version,v):semver.lt(version,v)))match=true;open=false;}
     if(v!=='0')prior=v;
    }
    if(open&&(!lower||semver.gte(version,lower)))match=true;
   }
   if(!a.versions&&!a.ranges?.length)throw Error('missing_affected_data');
  }
  if(!base.flaw_ref)throw Error('ambiguous_canonical_flaw');
  return {...base,state:match?'affected':'not-affected',reason:match?'exact_package_and_supported_range':'outside_affected_range'};
 }catch(e){return {...base,state:'held',reason:e instanceof Error?e.message:'unsupported_range'};}
}
export interface PublicPairs {approved:InventoryOccurrence[];held:{entry:string;reason:string}[];receipts:{sha256:string;retrieved_at:string;name:string;version:string;tarball:string;integrity:string}[];checked:string[];complete:boolean}
export async function verifyPublicPairs(http:PublicHTTP,occurrences:InventoryOccurrence[],resume?:PublicPairs,checkpoint:(v:PublicPairs)=>Promise<void>=async()=>{}){
 const state:PublicPairs=resume?structuredClone(resume):{approved:[],held:[],receipts:[],checked:[],complete:false};
 const pairs=new Map<string,InventoryOccurrence[]>();for(const o of occurrences){const key=JSON.stringify([o.name,o.version]);pairs.set(key,[...pairs.get(key)??[],o]);}
 for(const [key,group]of pairs){
  if(state.checked.includes(key))continue;const first=group[0]!;
  try{
   const response=await http.json(`https://registry.npmjs.org/${encodeURIComponent(first.name)}/${encodeURIComponent(first.version)}`);const m=z.object({name:z.string(),version:z.string(),dist:z.object({tarball:z.string(),integrity:z.string()})}).parse(response.body);
   if(m.name!==first.name||m.version!==first.version||group.some(o=>o.resolved!==m.dist.tarball||o.integrity!==m.dist.integrity))throw Error('public_identity_mismatch');
   state.approved.push(...group);state.receipts.push({sha256:response.sha256,retrieved_at:response.retrieved_at,name:m.name,version:m.version,...m.dist});
  }catch{state.held.push(...group.map(o=>({entry:o.entry,reason:'public_identity_unverified'})));}
  state.checked.push(key);await checkpoint(state);
 }
 state.complete=true;await checkpoint(state);return state;
}
export interface OsvQuery {package:{name:string;ecosystem:'npm'};version:string;page_token?:string}
export interface OsvQuarantine {id:string;sha256:string;retrieved_at:string;upstream_at:string;reason:string;evidence_complete:false}
export interface OsvCheckpoint {quarantined?:OsvQuarantine[];remaining:OsvQuery[];hits:{name:string;version:string;id:string;modified:string}[];seen_tokens:string[];records:{record:Advisory;sha256:string;retrieved_at:string}[];pending_ids:string[];pages:PublicResponse[];phase:'queries'|'records'|'complete'}
export async function queryOsv(http:PublicHTTP,occurrences:InventoryOccurrence[],resume?:OsvCheckpoint,checkpoint:(v:OsvCheckpoint)=>Promise<void>=async()=>{}){
 const pairs=new Map(occurrences.map(o=>[JSON.stringify([o.name,o.version]),{package:{name:o.name,ecosystem:'npm' as const},version:o.version}]));
 const state:OsvCheckpoint=resume?structuredClone(resume):{remaining:[...pairs.values()],hits:[],seen_tokens:[],records:[],pending_ids:[],pages:[],phase:'queries'};
 state.quarantined??=[];
 for(const q of state.remaining){if(!pairs.has(JSON.stringify([q.package.name,q.version]))||q.package.ecosystem!=='npm')throw Error('checkpoint_query_scope');}
 while(state.phase==='queries'&&state.remaining.length){
  const batch=state.remaining.slice(0,100),response=await http.json('https://api.osv.dev/v1/querybatch',{queries:batch},8*1024*1024);
  const result=z.object({results:z.array(z.object({vulns:z.array(z.object({id:OsvId,modified:z.iso.datetime({offset:true})})).optional(),next_page_token:z.string().min(1).max(2000).optional()}))}).parse(response.body);if(result.results.length!==batch.length)throw Error('osv_batch_identity');
  const next:OsvQuery[]=[];
  for(const [i,r]of result.results.entries()){
   const q=batch[i]!;for(const v of r.vulns??[])state.hits.push({name:q.package.name,version:q.version,id:v.id,modified:v.modified});
   if(r.next_page_token){const key=JSON.stringify([q.package.name,q.version,r.next_page_token]);if(state.seen_tokens.includes(key))throw Error('osv_repeated_page');state.seen_tokens.push(key);next.push({...q,page_token:r.next_page_token});}
  }
  state.remaining=[...next,...state.remaining.slice(batch.length)];state.pages.push(response);await checkpoint(state);
 }
 // A saved record is reused only while no hit names a later revision of it: a seeded record from an earlier query is read again once OSV has updated it.
 const stale=(id:string)=>state.records.some(r=>r.record.id===id&&state.hits.some(h=>h.id===id&&Date.parse(h.modified)>Date.parse(r.record.modified)));
 if(state.phase==='queries'){state.phase='records';state.pending_ids=[...new Set(state.hits.map(v=>v.id))].filter(id=>stale(id)||!state.records.some(r=>r.record.id===id));await checkpoint(state);}
 while(state.phase==='records'&&state.pending_ids.length){
  const id=OsvId.parse(state.pending_ids[0]),fetched=await fetchOsvRecord(http,id);
  if(!fetched.record){state.quarantined.push(fetched.quarantine!);state.records=state.records.filter(r=>r.record.id!==id);state.pending_ids.shift();await checkpoint(state);continue;}
  const record=fetched.record;
  if(state.hits.some(h=>h.id===id&&Date.parse(h.modified)>Date.parse(record.modified)))throw Error('osv_record_revision_mismatch');
  state.records=[...state.records.filter(r=>r.record.id!==id),{record,sha256:fetched.sha256,retrieved_at:fetched.retrieved_at}];state.pending_ids.shift();await checkpoint(state);
 }
 state.phase='complete';await checkpoint(state);return state;
}

export async function fetchOsvRecord(http:PublicHTTP,id:string){
 OsvId.parse(id);const response=await http.json(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`);
 if(z.object({id:OsvId}).parse(response.body).id!==id)throw Error('osv_record_identity');
 try{screenedJson(response.body);return {record:OsvRecord.parse(response.body),quarantine:null,sha256:response.sha256,retrieved_at:response.retrieved_at};}
 catch(e){const date=z.object({modified:z.iso.datetime({offset:true})}).safeParse(response.body);
  const quarantine:OsvQuarantine={id,sha256:response.sha256,retrieved_at:response.retrieved_at,upstream_at:date.success?date.data.modified:response.retrieved_at,reason:(e as {code?:string}).code==='security.secret'?'credential_shaped_evidence':'unsupported_advisory_schema',evidence_complete:false};
  return {record:null,quarantine,sha256:response.sha256,retrieved_at:response.retrieved_at};
 }
}
