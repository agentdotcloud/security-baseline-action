import assert from 'node:assert/strict';
import { test } from 'node:test';
import { DEPS_LOCK_VERSION, parseDepsLock } from '../src/security-deps-lock.ts';
// DFBASE-10: the static.deps lock model. The parity test against the pilot's npmInventory lives in control
// (packages/control/test/security-inventory.test.ts), because it imports the pilot parser.
const entry=(version='1.0.0')=>({version,resolved:`https://registry.npmjs.org/sample/-/sample-${version}.tgz`,integrity:'sha512-Zml4dHVyZQ=='});
const lock=(packages:unknown,lockfileVersion=3)=>JSON.stringify({lockfileVersion,packages});
const reg=(name:string,version:string,extra:Record<string,unknown>={})=>({version,resolved:`https://registry.npmjs.org/${name}/-/${name.split('/').at(-1)}-${version}.tgz`,integrity:'sha512-Zml4dHVyZQ==',...extra});
const tree={
 '':{name:'app',version:'1.0.0',workspaces:['packages/*'],dependencies:{a:'^1.0.0',w:'*'},devDependencies:{t:'~2.0.0'},optionalDependencies:{o:'^3.0.0'},peerDependencies:{p:'>=1'}},
 'node_modules/a':reg('a','1.2.0',{dependencies:{c:'^1.0.0'},peerDependencies:{p:'^1.0.0'}}),
 'node_modules/@s/c':reg('@s/c','2.0.0-beta.1+build',{dev:true,optional:true}),
 'node_modules/a/node_modules/c':reg('c','1.0.0'),
 'node_modules/t':reg('t','2.0.1',{dev:true}),
 'node_modules/w':{resolved:'packages/w',link:true},
 'packages/w':{name:'w',version:'0.1.0',dependencies:{a:'~1.2.0'},devDependencies:{t:'^2.0.0'}},
 'packages/w/node_modules/a':reg('a','1.0.0'),
 'node_modules/alias':reg('real','1.0.0',{name:'real',dependencies:{a:'^1.0.0'}}),
 'node_modules/git':{version:'1.0.0',resolved:'git+ssh://git@example.test/x.git#abc',dependencies:{a:'^1.0.0'}},
};
test('DFBASE-10: lockfile v2 and v3 read the same packages section into the same entries; the v2 legacy tree is ignored',()=>{
 const v3=parseDepsLock(lock(tree,3)),v2=parseDepsLock(JSON.stringify({lockfileVersion:2,packages:tree,dependencies:{a:{version:'9.9.9'},evil:{version:'1.0.0'}}}));
 assert.equal(v3.state,'parsed');assert.equal(v2.state,'parsed');assert.equal(v3.lockfile_version,3);assert.equal(v2.lockfile_version,2);
 assert.equal(v3.parser_version,DEPS_LOCK_VERSION);assert.equal(DEPS_LOCK_VERSION,'npm-lock-v2v3/semver-7.8.6/deps-v2');
 assert.deepEqual(v2.entries,v3.entries);assert.deepEqual(v2.root,v3.root);
 assert.ok(!v2.entries.some(e=>e.name==='evil'||e.version==='9.9.9'));
 assert.deepEqual(parseDepsLock(Buffer.from(lock(tree,3))),v3,'bytes and text parse alike');
});
test('DFBASE-10: lockfile v1, any other version and a lockfile with no packages section are unsupported',()=>{
 for(const [doc,version] of [[{lockfileVersion:1,dependencies:{a:{version:'1.0.0'}}},1],[{lockfileVersion:4,packages:tree},4],[{lockfileVersion:3},3],[{lockfileVersion:2,dependencies:{}},2],[{lockfileVersion:3,packages:[]},3],[{lockfileVersion:'3',packages:tree},null],[[],null]] as const){
  const result=parseDepsLock(JSON.stringify(doc));
  assert.deepEqual(result,{parser_version:DEPS_LOCK_VERSION,state:'unsupported',reason:'unsupported_lockfile',lockfile_version:version,root:null,entries:[]});
 }
});
test('DFBASE-10: declared ranges are kept for the root, registry, nested, held and first-party entries',()=>{
 const result=parseDepsLock(lock(tree)),at=(path:string)=>result.entries.find(e=>e.path===path)!;
 assert.deepEqual(result.root,{present:true,name:'app',version:'1.0.0',dependencies:{a:'^1.0.0',w:'*'},devDependencies:{t:'~2.0.0'},optionalDependencies:{o:'^3.0.0'},peerDependencies:{p:'>=1'}});
 assert.deepEqual(at('node_modules/a'),{path:'node_modules/a',name:'a',version:'1.2.0',kind:'registry',hold_reason:null,resolved:reg('a','1.2.0').resolved,integrity:'sha512-Zml4dHVyZQ==',dev:false,optional:false,dependencies:{c:'^1.0.0'},optionalDependencies:{},peerDependencies:{p:'^1.0.0'},devDependencies:{}});
 assert.deepEqual([at('node_modules/@s/c').name,at('node_modules/@s/c').version,at('node_modules/@s/c').dev,at('node_modules/@s/c').optional],['@s/c','2.0.0-beta.1+build',true,true]);
 assert.equal(at('node_modules/a/node_modules/c').kind,'registry');
 assert.deepEqual([at('packages/w').kind,at('packages/w').name,at('packages/w').dependencies,at('packages/w').devDependencies],['first_party','w',{a:'~1.2.0'},{t:'^2.0.0'}]);
 assert.deepEqual([at('node_modules/alias').kind,at('node_modules/alias').hold_reason,at('node_modules/alias').name,at('node_modules/alias').dependencies],['held','npm_alias_requires_review','alias',{a:'^1.0.0'}]);
 assert.deepEqual([at('node_modules/git').kind,at('node_modules/git').hold_reason,at('node_modules/git').dependencies],['held','unsupported_entry',{a:'^1.0.0'}]);
 const unreadable=parseDepsLock(lock({'':{dependencies:'a'},'node_modules/x':{...reg('x','1.0.0'),dependencies:{a:1},peerDependencies:[]},'node_modules/y':'nonsense'}));
 assert.deepEqual([unreadable.root!.dependencies,unreadable.root!.devDependencies],[null,{}],'present but unreadable is null; absent is empty');
 assert.deepEqual([unreadable.entries[0]!.kind,unreadable.entries[0]!.dependencies,unreadable.entries[0]!.peerDependencies,unreadable.entries[0]!.optionalDependencies],['registry',null,null,{}]);
 assert.deepEqual([unreadable.entries[1]!.kind,unreadable.entries[1]!.hold_reason,unreadable.entries[1]!.dependencies],['held','unsupported_entry',null]);
 const rootless=parseDepsLock(lock({'node_modules/x':reg('x','1.0.0')}));
 assert.deepEqual(rootless.root,{present:false,name:null,version:null,dependencies:null,optionalDependencies:null,peerDependencies:null,devDependencies:null});
 const proto=parseDepsLock('{"lockfileVersion":3,"packages":{"":{"dependencies":{"__proto__":"^1.0.0","a":"1"}}}}');
 assert.deepEqual(Object.keys(proto.root!.dependencies!),['__proto__','a']);assert.equal(Object.getPrototypeOf(proto.root!.dependencies),Object.prototype);
});
test('DFBASE-10: links and workspace folders are first-party, neither dependencies nor holds; a workspace\'s own node_modules holds dependencies',()=>{
 const result=parseDepsLock(lock(tree)),kinds=Object.fromEntries(result.entries.map(e=>[e.path,e.kind]));
 assert.deepEqual(kinds,{'node_modules/a':'registry','node_modules/@s/c':'registry','node_modules/a/node_modules/c':'registry','node_modules/t':'registry','node_modules/w':'first_party','packages/w':'first_party','packages/w/node_modules/a':'registry','node_modules/alias':'held','node_modules/git':'held'});
 assert.ok(result.entries.filter(e=>e.kind==='first_party').every(e=>e.hold_reason===null));
 assert.equal(result.entries.find(e=>e.path==='node_modules/w')!.name,'w');
});
test('DFBASE-10: DFINT-17 per-entry holds carry over with their reasons',()=>{
 const cases:[string,unknown,string][]=[
  ['node_modules/sample',{...entry(),name:'different'},'npm_alias_requires_review'],['node_modules/sample',{...entry(),version:'latest'},'unsupported_exact_version'],
  ['node_modules/sample',{...entry(),resolved:'git+https://example.test/x.git'},'not_approved_public_registry'],['node_modules/sample',{...entry(),resolved:'../x.tgz'},'unsupported_entry'],['node_modules/sample',{...entry(),resolved:'https://private.test/sample.tgz'},'not_approved_public_registry'],
  ['node_modules/sample',{...entry(),resolved:'https://registry.npmjs.org:8443/sample.tgz'},'not_approved_public_registry'],['node_modules/sample',{...entry(),integrity:'md5-x'},'unsupported_integrity'],
  ['node_modules/sample',{version:'1.0.0'},'unsupported_entry'],['node_modules/sample',[],'unsupported_entry'],['node_modules/Bad',entry(),'unsupported_entry'],
  ['node_modules/../x',entry(),'unsupported_entry'],['packages/node_modules',entry(),'unsupported_entry'],
 ];
 for(const [path,value,reason] of cases){const e=parseDepsLock(lock({'':{},[path]:value})).entries[0]!;assert.deepEqual([e.kind,e.hold_reason],['held',reason],`${path} ${JSON.stringify(value)}`);}
 const deep='node_modules/p/'.repeat(34)+'node_modules/sample',long=parseDepsLock(lock({'':{},[deep]:{...entry(),dependencies:{a:'~1.0.0'}}})).entries[0]!;
 assert.deepEqual([long.kind,long.hold_reason,long.name,long.dependencies],['held','unsupported_entry','sample',{a:'~1.0.0'}],'a key past the evidence path bound is held with its installed name and ranges');
});
test('DFBASE-10: a bundled entry, and an entry whose resolved path is not its own name\'s on the public registry, are held',()=>{
 const at=(path:string,value:unknown)=>{const e=parseDepsLock(lock({'':{},[path]:value})).entries[0]!;return [e.kind,e.hold_reason,e.name];};
 // npm writes a bundled entry with no resolved or integrity. One that carries both is held the same way, ahead of the shape rules.
 assert.deepEqual(at('node_modules/parent/node_modules/inner',{version:'1.0.0',inBundle:true}),['held','bundled_dependency','inner']);
 assert.deepEqual(at('node_modules/parent/node_modules/inner',reg('inner','1.0.0',{inBundle:true})),['held','bundled_dependency','inner']);
 assert.deepEqual(at('node_modules/inner',reg('inner','1.0.0',{inBundle:false})),['registry',null,'inner']);
 assert.deepEqual(at('node_modules/inner',reg('inner','1.0.0',{inBundle:'yes'})),['held','unsupported_entry','inner']);
 // An alias npm wrote no name for: the URL names another package, or no package's tarball at all.
 for(const resolved of [reg('bar','1.0.0').resolved,'https://registry.npmjs.org/foobar/-/foobar-1.0.0.tgz','https://registry.npmjs.org/foo.tgz','https://registry.npmjs.org/foo/-',
  'https://registry.npmjs.org/foo/-/../../bar/-/bar-1.0.0.tgz','https://registry.npmjs.org/@s/foo/-/foo-1.0.0.tgz','https://registry.npmjs.org/%66oo/-/foo-1.0.0.tgz','https://registry.npmjs.org/FOO/-/foo-1.0.0.tgz'])
  for(const extra of [{},{name:'foo'}])assert.deepEqual(at('node_modules/foo',{...reg('foo','1.0.0'),...extra,resolved}),['held','npm_alias_requires_review','foo'],resolved);
 assert.deepEqual(at('node_modules/@s/foo',reg('foo','1.0.0')),['held','npm_alias_requires_review','@s/foo']);
 // A private or redirected source is still named as that, not as an alias.
 assert.deepEqual(at('node_modules/foo',{...reg('foo','1.0.0'),resolved:'https://private.test/bar/-/bar-1.0.0.tgz'}),['held','not_approved_public_registry','foo']);
 // The name is the one the entry is installed under, at any depth and with a scope.
 assert.deepEqual(at('node_modules/a/node_modules/foo',reg('foo','1.0.0')),['registry',null,'foo']);
 assert.deepEqual(at('node_modules/@s/foo',reg('@s/foo','1.0.0',{name:'@s/foo'})),['registry',null,'@s/foo']);
 // A held entry keeps its ranges and its place in the tree, like every other hold.
 const kept=parseDepsLock(lock({'':{},'node_modules/foo':reg('bar','1.0.0',{dependencies:{a:'^1.0.0'}}),'node_modules/p/node_modules/q':{version:'1.0.0',inBundle:true,dependencies:{a:'~1.0.0'}}})).entries;
 assert.deepEqual(kept.map(e=>[e.kind,e.dependencies]),[['held',{a:'^1.0.0'}],['held',{a:'~1.0.0'}]]);
});
test('DFBASE-10: a credential-shaped lockfile is refused whole, with nothing derived from it to store',()=>{
 const secret=['ghp','_','A'.repeat(36)].join(''); // a GitHub token's shape, never a real one
 for(const doc of [{lockfileVersion:3,packages:{'node_modules/a':reg('a','1.0.0',{resolved:`https://x:${secret}@registry.npmjs.org/a.tgz`})}},{lockfileVersion:1,note:secret}]){
  const result=parseDepsLock(JSON.stringify(doc));
  assert.deepEqual(result,{parser_version:DEPS_LOCK_VERSION,state:'credential_shaped',reason:'credential_shaped_content',lockfile_version:null,root:null,entries:[]});
  assert.ok(!JSON.stringify(result).includes(secret));
 }
});
test('DFBASE-10: malformed JSON or UTF-8 is malformed; a byte-order mark is not; over 2 MiB is refused before parsing',()=>{
 for(const input of ['{',Buffer.from([0x7b,0xff,0x7d])])assert.deepEqual(parseDepsLock(input),{parser_version:DEPS_LOCK_VERSION,state:'malformed',reason:'malformed_json',lockfile_version:null,root:null,entries:[]});
 assert.equal(parseDepsLock(Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),Buffer.from(lock(tree))])).state,'parsed');
 assert.throws(()=>parseDepsLock(' '.repeat(2*1024*1024+1)),/deps_lock_oversize/);
 assert.throws(()=>parseDepsLock(new Uint8Array(2*1024*1024+1)),/deps_lock_oversize/);
});
