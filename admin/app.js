const $=id=>document.getElementById(id), C=window.PA_CONFIG;
const say=(t,bad)=>{$('msg').textContent=t||'';$('msg').style.color=bad?'#b00':'#060'};
if(!C.SUPABASE_URL||!C.SUPABASE_ANON_KEY){say('Set SUPABASE_URL and SUPABASE_ANON_KEY in config.js',1)}
const sb=supabase.createClient(C.SUPABASE_URL||'http://x',C.SUPABASE_ANON_KEY||'x');
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const ok=async(p)=>{const r=await p;if(r.error){say(r.error.message,1);throw r.error}return r.data};
let factor;
$('doLogin').onclick=async()=>{try{await ok(sb.auth.signInWithPassword({email:$('em').value,password:$('pw').value}));
 const f=await ok(sb.auth.mfa.listFactors());factor=f.totp[0];
 if(!factor){say('Enrol a TOTP factor first (Supabase Auth MFA is free).',1);return}
 $('mfa').classList.remove('hide')}catch(e){}};
$('doOtp').onclick=async()=>{try{const ch=await ok(sb.auth.mfa.challenge({factorId:factor.id}));
 await ok(sb.auth.mfa.verify({factorId:factor.id,challengeId:ch.id,code:$('otp').value}));
 $('login').classList.add('hide');$('app').classList.remove('hide');say('');load()}catch(e){}};
let P='passaura';
async function load(){
 const pr=await ok(sb.from('projects').select('*').order('slug'));$('proj').innerHTML=pr.map(x=>`<option value="${esc(x.slug)}">${esc(x.name)}</option>`).join('');$('proj').value=P;
 const cfg=(await ok(sb.from('admin_config').select('*').eq('id',1).single()));
 $('mode').value=cfg.mode;$('scope').value=cfg.paid_scope;$('paused').checked=cfg.invites_paused;
 const inv=await ok(sb.from('invites').select('id,created_at,used_by_device').order('created_at',{ascending:false}).limit(100));
 $('invT').innerHTML='<tr><th>id</th><th>state</th><th></th></tr>'+inv.map(i=>`<tr><td>${esc(i.id)}</td><td>${i.used_by_device?'used':'open'}</td><td>${i.used_by_device?'':`<button data-inv="${esc(i.id)}">Revoke</button>`}</td></tr>`).join('');
 const dev=await ok(sb.from('devices').select('id,registered_at,is_seed,revoked').order('registered_at',{ascending:false}).limit(200));
 $('devT').innerHTML='<tr><th>device</th><th>registered</th><th>seed</th><th>status</th><th></th></tr>'+dev.map(d=>`<tr><td>${esc(d.id)}</td><td>${esc(d.registered_at)}</td><td>${d.is_seed?'yes':''}</td><td>${d.revoked?'revoked':'active'}</td><td><button data-dev="${esc(d.id)}" data-r="${!d.revoked}">${d.revoked?'Restore':'Revoke'}</button></td></tr>`).join('');
 const k=await ok(sb.from('premium_keys').select('id,plan,expires_at,revoked,redeemed_at').eq('project',P).order('created_at',{ascending:false}).limit(100));
 $('keyT').innerHTML='<tr><th>id</th><th>plan</th><th>expires</th><th>state</th><th></th></tr>'+k.map(x=>`<tr><td>${esc(x.id)}</td><td>${esc(x.plan)}</td><td>${esc(x.expires_at)}</td><td>${x.revoked?'revoked':x.redeemed_at?'redeemed':'open'}</td><td>${x.revoked?'':`<button data-key="${esc(x.id)}">Revoke</button>`}</td></tr>`).join('');
 const f=await ok(sb.from('feature_flags').select('*').eq('project',P).order('key'));
 $('flagT').innerHTML=f.map(x=>`<tr><td>${esc(x.key)}</td><td>${esc(JSON.stringify(x.value))}</td></tr>`).join('');
 const a=await ok(sb.from('announcements').select('*').eq('project',P).order('created_at',{ascending:false}).limit(50));
 $('annT').innerHTML=a.map(x=>`<tr><td>${esc(x.title)}</td><td>${esc(x.body)}</td><td><button data-ann="${esc(x.id)}" data-p="${!x.published}">${x.published?'Unpublish':'Publish'}</button></td></tr>`).join('')}
$('saveCfg').onclick=async()=>{await ok(sb.from('admin_config').update({mode:$('mode').value,paid_scope:$('scope').value,invites_paused:$('paused').checked,updated_at:new Date().toISOString()}).eq('id',1));say('Saved');load()};
$('issue').onclick=async()=>{const c=await ok(sb.rpc('admin_issue_invites',{p_count:+$('n').value}));$('codes').textContent='Copy now, shown once:\n'+c.join('\n');load()};
$('mkKey').onclick=async()=>{const c=await ok(sb.rpc('admin_issue_premium_key',{p_plan:$('plan').value,p_days:+$('days').value,p_project:P}));$('keyOut').textContent='Copy now, shown once: '+c;load()};
$('saveFlag').onclick=async()=>{let v;try{v=JSON.parse($('fv').value)}catch{say('Value must be valid JSON',1);return}
 await ok(sb.from('feature_flags').upsert({project:P,key:$('fk').value,value:v,updated_at:new Date().toISOString()}));load()};
$('addAnn').onclick=async()=>{await ok(sb.from('announcements').insert({project:P,title:$('at').value,body:$('ab').value}));load()};
document.addEventListener('click',async e=>{const d=e.target.dataset;if(!d)return;
 if(d.inv)await ok(sb.rpc('admin_revoke_invite',{p_id:d.inv}));
 else if(d.dev&&!confirm('Change this member status? Only the owner can do this.'))return;
 else if(d.dev)await ok(sb.rpc('admin_set_device_revoked',{p_id:d.dev,p_revoked:d.r==='true'}));
 else if(d.key)await ok(sb.rpc('admin_revoke_premium_key',{p_id:d.key}));
 else if(d.ann)await ok(sb.from('announcements').update({published:d.p==='true'}).eq('id',d.ann));
 else return;load()});

$('proj').onchange=()=>{P=$('proj').value;load()};
$('addProj').onclick=async()=>{await ok(sb.from('projects').insert({slug:$('np').value,name:$('nn').value}));P=$('np').value;load()};
