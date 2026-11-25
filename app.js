var KINDS=[
{v:'tasks',l:'مهام اليوم Tasks',add:'مهمة Task',hint:'المهمة Task',dl:'الموعد Due date',empty:'مفيش مهام لسه. No tasks yet.'},
{v:'meetings',l:'اجتماعات ومواعيد Meetings',add:'اجتماع Meeting',hint:'الاجتماع (مع مين؟) Meeting with',dl:'التاريخ Date',empty:'مفيش مواعيد لسه. No meetings yet.'},
{v:'letters',l:'خطابات Letters',add:'خطاب Letter',hint:'الخطاب أو الإيميل (لمين؟) Letter to',dl:'تاريخ الإرسال Send date',empty:'مفيش مراسلات لسه. No letters yet.'},
{v:'docs',l:'مستندات Documents',add:'مستند Document',hint:'اسم المستند Document name',dl:'التاريخ Date',empty:'مفيش مستندات لسه. No documents yet.'},
{v:'followups',l:'متابعات Follow-ups',add:'متابعة Follow-up',hint:'إيه المطلوب متابعته؟ What to follow up',dl:'موعد المتابعة Follow-up date',empty:'مفيش متابعات لسه. No follow-ups yet.'}];
var $=function(s){return document.querySelector(s)};
var enc=new TextEncoder();
function b64(buf){return btoa(String.fromCharCode.apply(null,new Uint8Array(buf)))}
function unb64(s){return Uint8Array.from(atob(s),function(c){return c.charCodeAt(0)})}
var SHA_K=new Int32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
var SHA_IV=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
function shaCompress(H,W){var w=new Int32Array(64),i,a,b,c,d,e,f,g,h,t1,t2,s0,s1;for(i=0;i<16;i++)w[i]=W[i];
 for(i=16;i<64;i++){s0=((w[i-15]>>>7)|(w[i-15]<<25))^((w[i-15]>>>18)|(w[i-15]<<14))^(w[i-15]>>>3);s1=((w[i-2]>>>17)|(w[i-2]<<15))^((w[i-2]>>>19)|(w[i-2]<<13))^(w[i-2]>>>10);w[i]=(w[i-16]+s0+w[i-7]+s1)|0}
 a=H[0];b=H[1];c=H[2];d=H[3];e=H[4];f=H[5];g=H[6];h=H[7];
 for(i=0;i<64;i++){s1=((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7));t1=(h+s1+((e&f)^(~e&g))+SHA_K[i]+w[i])|0;s0=((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10));t2=(s0+((a&b)^(a&c)^(b&c)))|0;h=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0}
 H[0]=(H[0]+a)|0;H[1]=(H[1]+b)|0;H[2]=(H[2]+c)|0;H[3]=(H[3]+d)|0;H[4]=(H[4]+e)|0;H[5]=(H[5]+f)|0;H[6]=(H[6]+g)|0;H[7]=(H[7]+h)|0}
function shaBytes(H,bytes,prevLen){var n=bytes.length,total=prevLen+n,len=((n+9+63)>>6)<<6,buf=new Uint8Array(len),W=new Int32Array(16),i,j;buf.set(bytes);buf[n]=0x80;var bits=total*8;buf[len-4]=(bits>>>24)&255;buf[len-3]=(bits>>>16)&255;buf[len-2]=(bits>>>8)&255;buf[len-1]=bits&255;
 for(i=0;i<len;i+=64){for(j=0;j<16;j++)W[j]=(buf[i+4*j]<<24)|(buf[i+4*j+1]<<16)|(buf[i+4*j+2]<<8)|buf[i+4*j+3];shaCompress(H,W)}}
function shaOut(H){var o=new Uint8Array(32),i;for(i=0;i<8;i++){o[4*i]=H[i]>>>24;o[4*i+1]=(H[i]>>>16)&255;o[4*i+2]=(H[i]>>>8)&255;o[4*i+3]=H[i]&255}return o}
function jsPbkdf2(pwd,salt,iters){var key=pwd;if(key.length>64){var Hk=new Int32Array(SHA_IV);shaBytes(Hk,key,0);key=shaOut(Hk)}
 var ip=new Uint8Array(64),op=new Uint8Array(64),i,j;for(i=0;i<64;i++){var kb=i<key.length?key[i]:0;ip[i]=kb^0x36;op[i]=kb^0x5c}
 var Hi=new Int32Array(SHA_IV),Ho=new Int32Array(SHA_IV);shaBytes(Hi,ip,0);Hi=new Int32Array(SHA_IV);var Wp=new Int32Array(16);
 var blk=function(b){for(var q=0;q<16;q++)Wp[q]=(b[4*q]<<24)|(b[4*q+1]<<16)|(b[4*q+2]<<8)|b[4*q+3]};
 blk(ip);shaCompress(Hi,Wp);blk(op);shaCompress(Ho,Wp);
 var s1=new Uint8Array(salt.length+4);s1.set(salt);s1[salt.length+3]=1;
 var H=new Int32Array(Hi);shaBytes(H,s1,64);var U=shaOut(H);
 H=new Int32Array(Ho);shaBytes(H,U,64);U=shaOut(H);var T=new Int32Array(8);
 var uw=new Int32Array(8);for(j=0;j<8;j++){uw[j]=(U[4*j]<<24)|(U[4*j+1]<<16)|(U[4*j+2]<<8)|U[4*j+3];T[j]=uw[j]}
 var W=new Int32Array(16);for(i=1;i<iters;i++){
  W.fill(0);for(j=0;j<8;j++)W[j]=uw[j];W[8]=0x80000000|0;W[15]=768;var Hh=new Int32Array(Hi);shaCompress(Hh,W);
  for(j=0;j<8;j++)W[j]=Hh[j];W[8]=0x80000000|0;for(j=9;j<15;j++)W[j]=0;W[15]=768;Hh=new Int32Array(Ho);shaCompress(Hh,W);
  for(j=0;j<8;j++){uw[j]=Hh[j];T[j]^=Hh[j]}}
 var out=new Uint8Array(32);for(j=0;j<8;j++){out[4*j]=T[j]>>>24;out[4*j+1]=(T[j]>>>16)&255;out[4*j+2]=(T[j]>>>8)&255;out[4*j+3]=T[j]&255}return out}

function normDigits(p){return String(p).replace(/[\u0660-\u0669]/g,function(c){return c.charCodeAt(0)-1632}).replace(/[\u06F0-\u06F9]/g,function(c){return c.charCodeAt(0)-1776})}
async function hashPin(pin,salt){var data=enc.encode(pin);try{if(window.crypto&&crypto.subtle){var k=await crypto.subtle.importKey('raw',data,'PBKDF2',false,['deriveBits']);return b64(await crypto.subtle.deriveBits({name:'PBKDF2',salt:salt,iterations:150000,hash:'SHA-256'},k,256))}}catch(e){}return b64(jsPbkdf2(data,salt,150000))}
function rndSalt(){var a=new Uint8Array(16);try{crypto.getRandomValues(a)}catch(e){for(var i=0;i<16;i++)a[i]=Math.floor(Math.random()*256)}return a}
function load(k,d){try{var v=localStorage.getItem(k);return v?JSON.parse(v):d}catch(e){return d}}
function save(k,v){try{localStorage.setItem(k,JSON.stringify(v));return true}catch(e){alert('تعذر الحفظ Could not save');return false}}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
var S={filter:'all',tab:'work',kind:'tasks',showCo:false,showItem:false,companies:load('sh.companies',[]),items:load('sh.items',[]),devs:load('sh.devs',[]),showDev:false,editDev:0,editItem:0,editCo:false,active:load('sh.active',0)};
var BRAND='<div class="brand noprint"><svg viewBox="0 0 320 110" width="100%" height="110" aria-hidden="true"><defs><linearGradient id="g1" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#ff6fa8"/><stop offset="1" stop-color="#ffb84d"/></linearGradient><linearGradient id="g2" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#4dd0e1"/><stop offset="1" stop-color="#9b6bff"/></linearGradient></defs><g transform="translate(232 8) rotate(12 40 40)"><path d="M40 40 C 10 -8, -14 20, 8 42 C -6 56, 16 80, 40 48 Z" fill="url(#g1)" stroke="#d6336c" stroke-width="2.5" stroke-linejoin="round"/><path d="M40 40 C 70 -8, 94 20, 72 42 C 86 56, 64 80, 40 48 Z" fill="url(#g2)" stroke="#6741d9" stroke-width="2.5" stroke-linejoin="round"/><circle cx="20" cy="30" r="5" fill="#fff" opacity=".8"/><circle cx="60" cy="30" r="5" fill="#fff" opacity=".8"/><path d="M40 30 L40 62" stroke="#3b2a50" stroke-width="5" stroke-linecap="round"/><path d="M40 30 C 36 16, 28 12, 26 8 M40 30 C 44 16, 52 12, 54 8" stroke="#3b2a50" stroke-width="2" fill="none" stroke-linecap="round"/></g><text x="8" y="78" textLength="212" lengthAdjust="spacingAndGlyphs" class="bn" fill="#e8590c" stroke="#862e9c" stroke-width="1">shahira</text><path d="M10 92 C 60 100, 120 86, 200 94" stroke="#20c997" stroke-width="4" fill="none" stroke-linecap="round" stroke-dasharray="2 8"/></svg></div>';

/* ---- backup ---- */
/* ---- status ---- */
function dayDiff(ds){var p=String(ds).split('-');if(p.length<3)return null;var t=new Date(),a=Date.UTC(t.getFullYear(),t.getMonth(),t.getDate()),b=Date.UTC(+p[0],+p[1]-1,+p[2]);if(isNaN(b))return null;return Math.round((b-a)/864e5)}
function stFrom(done,date){if(done)return {k:'done',ar:'تمّت',en:'Done'};var d=date?dayDiff(date):null;
  if(d===null)return {k:'none',ar:'قيد الانتظار',en:'Pending'};
  if(d<0)return {k:'over',ar:'متأخر '+(-d)+' يوم',en:'Overdue '+(-d)+(d===-1?' day':' days')};
  if(d===0)return {k:'today',ar:'النهاردة',en:'Today'};
  if(d===1)return {k:'soon',ar:'بكرة',en:'Tomorrow'};
  return {k:'soon',ar:'بعد '+d+' يوم',en:'In '+d+' days'}}
function itemSt(i){return stFrom(i.done,i.date)}
function devSt(d){return stFrom(d.contacted,d.pdate)}
function stBadge(st){return '<span class="st st-'+st.k+'">'+(st.k==='done'?'✓ ':'')+st.ar+' · '+st.en+'</span>'}
function stText(st){return st.ar+' '+st.en}
function fltRow(){var F=[['all','الكل All'],['up','القادم Upcoming'],['done','المنتهي Done']];return '<div class="row noprint">'+F.map(function(f){return '<button class="chip'+(S.filter===f[0]?' on':'')+'" data-flt="'+f[0]+'">'+f[1]+'</button>'}).join('')+'</div>'}
function fltOk(done){return S.filter==='all'||(S.filter==='done'?done:!done)}
function sumLine(sts){var c={over:0,today:0,soon:0,none:0,done:0};sts.forEach(function(x){c[x.k]++});return '<div class="sum noprint"><span class="st st-over">'+c.over+' متأخر Overdue</span> <span class="st st-today">'+c.today+' النهاردة Today</span> <span class="st st-soon">'+(c.soon)+' قادم Upcoming</span> '+(c.none?'<span class="st st-none">'+c.none+' قيد الانتظار Pending</span> ':'')+'<span class="st st-done">'+c.done+' ✓ تمّت Done</span></div>'}
(function(){var st=document.createElement('style');st.textContent='.st{display:inline-block;padding:3px 10px;border-radius:999px;font-size:13px;font-weight:700;margin:2px 0}.st-soon{background:#0b5fff;color:#fff}.st-today{background:#ffb300;color:#3b2a00}.st-over{background:#c40000;color:#fff}.st-none{background:#e1d9ff;color:#2a1a66}.st-done{background:#37474f;color:#fff}.sum{margin:8px 0;line-height:2}.item.is-over{border-inline-start:8px solid #c40000}.item.is-today{border-inline-start:8px solid #ffb300}.item.is-soon{border-inline-start:8px solid #0b5fff}.item.is-done{border-inline-start:8px solid #37474f;opacity:.7;background:#eceff1}.item.is-done b{text-decoration:line-through}';document.head.appendChild(st)})();
/* ---- attachments (IndexedDB) ---- */
var MAXF=10*1024*1024,MAXBK=20*1024*1024,PF=null,RMF=false;
function fdb(){return new Promise(function(res,rej){if(!window.indexedDB)return rej(new Error('noidb'));var r=indexedDB.open('shahira-files',1);r.onupgradeneeded=function(){r.result.createObjectStore('f')};r.onsuccess=function(){res(r.result)};r.onerror=function(){rej(r.error)}})}
function fTx(mode,fn){return fdb().then(function(db){return new Promise(function(res,rej){var t=db.transaction('f',mode),q=fn(t.objectStore('f'));t.oncomplete=function(){res(q&&q.result)};t.onerror=t.onabort=function(){rej(t.error||new Error('tx'))}})})}
function readBuf(file){return new Promise(function(res,rej){var r=new FileReader();r.onload=function(){res(r.result)};r.onerror=function(){rej(r.error)};r.readAsArrayBuffer(file)})}
function fPut(id,file){return readBuf(file).then(function(buf){return fTx('readwrite',function(st){return st.put({name:file.name,type:file.type||'',buf:buf},id)})})}
function fPutBuf(id,name,type,buf){return fTx('readwrite',function(st){return st.put({name:name,type:type,buf:buf},id)})}
function fGet(id){return fTx('readonly',function(st){return st.get(id)})}
function fDel(id){return fTx('readwrite',function(st){return st.delete(id)})}
function fClear(){return fTx('readwrite',function(st){return st.clear()})}
function bufB64(buf){var u=new Uint8Array(buf),o='',i;for(i=0;i<u.length;i+=32768)o+=String.fromCharCode.apply(null,u.subarray(i,i+32768));return btoa(o)}
function b64Buf(b){var bs=atob(b),u=new Uint8Array(bs.length),i;for(i=0;i<bs.length;i++)u[i]=bs.charCodeAt(i);return u.buffer}
function fmtSize(n){return n>=1048576?(n/1048576).toFixed(1)+' MB':Math.max(1,Math.round(n/1024))+' KB'}
function filesTotal(){var t=0,c=0;S.items.forEach(function(i){if(i.file){t+=i.file.size||0;c++}});return {n:c,size:t}}
function collectFiles(){var ft=filesTotal();if(!ft.n)return Promise.resolve({files:{},skipped:false});if(ft.size>MAXBK)return Promise.resolve({files:{},skipped:true});
  var out={},ps=S.items.filter(function(i){return i.file}).map(function(i){return fGet(i.id).then(function(r){if(r)out[i.id]={name:r.name,type:r.type,data:bufB64(r.buf)}}).catch(function(){})});
  return Promise.all(ps).then(function(){return {files:out,skipped:false}})}
function openFile(id,dl){var isView=false;var w=null;
  fGet(id).then(function(r){if(!r){alert('الملف مش موجود على الموبايل ده (ممكن النسخة الاحتياطية ما فيهاش المرفقات).\nFile not found on this phone (the backup may not have included attachments).');return}
    var blob=new Blob([r.buf],{type:r.type||'application/octet-stream'}),u=URL.createObjectURL(blob);
    var view=!dl&&/^(application\/pdf|image\/)/.test(r.type||'');
    if(view){window.open(u,'_blank')||(location.href=u)}
    else{var a=document.createElement('a');a.href=u;a.download=r.name||'file';document.body.appendChild(a);a.click();a.remove()}
    setTimeout(function(){URL.revokeObjectURL(u)},60000)}).catch(function(){alert('تعذر فتح الملف Could not open the file')})}
function makeBackup(files){var o={app:'shahira',v:2,at:new Date().toISOString(),pin:load('sh.pin',null),companies:S.companies,items:S.items,devs:S.devs,active:S.active};if(files&&Object.keys(files).length)o.files=files;return JSON.stringify(o)}

function lastBk(){return localStorage.getItem('sh.lastbk')||''}
function markBk(){localStorage.setItem('sh.lastbk',new Date().toISOString());localStorage.setItem('sh.bksig',bkSig())}
function bkSig(){return JSON.stringify([load('sh.pin',null),S.companies,S.items,S.devs])}
function bkDirty(){if(!S.companies.length&&!S.items.length&&!S.devs.length)return false;return localStorage.getItem('sh.bksig')!==bkSig()}
function askLock(){
  if(!bkDirty()){showLock();return}
  var m=document.createElement('div');m.className='modal noprint';
  m.innerHTML='<div class="mbox"><h2>احفظي قبل القفل<br>Save first before locking</h2><p>في تغييرات لسه ما اتحفظتش في ملف نسخة احتياطية.<br>You have changes that are not in a saved backup file.</p><button class="btn pri" id="lk_save">حفظ Save</button></div>';
  document.body.appendChild(m);hist();
  var close=function(){m.remove()};
  m.querySelector('#lk_save').onclick=function(){close();exportBackup(null,function(){showLock()})};
}

function fmtD(i){if(!i)return 'لسه مفيش never';try{return new Date(i).toLocaleString()}catch(e){return i}}
function bkDue(){var l=lastBk();return !l||Date.now()-new Date(l).getTime()>864e5}
function autoCopy(){if(!S.companies.length&&!S.items.length&&!S.devs.length)return;var a=localStorage.getItem('sh.autoat');if(a&&Date.now()-new Date(a).getTime()<=864e5)return;try{var old=localStorage.getItem('sh.auto');if(old)localStorage.setItem('sh.auto2',old);localStorage.setItem('sh.auto',makeBackup());localStorage.setItem('sh.autoat',new Date().toISOString())}catch(e){}}
function restoreAuto(msg){var t=localStorage.getItem('sh.auto');if(!t){msg.textContent='مفيش نسخة داخل المتصفح لسه. No in-browser copy yet.';return}
  if(!confirm('هتتبدل بياناتك الحالية بآخر نسخة تلقائية ('+fmtD(localStorage.getItem('sh.autoat'))+'). Replace current data with the last automatic copy?'))return;
  var o;try{o=JSON.parse(t)}catch(e){msg.textContent='النسخة تالفة. Copy is damaged.';return}
  save('sh.companies',o.companies);save('sh.items',o.items);save('sh.devs',o.devs);save('sh.active',o.active||0);S.companies=o.companies;S.items=o.items;S.devs=o.devs;S.active=o.active||0;render()}
function exportBackup(msg,cb){collectFiles().then(function(r){exportNow(msg,cb,r)},function(){exportNow(msg,cb,{files:{},skipped:filesTotal().n>0})})}
function exportNow(msg,cb,r){
  var d=new Date(),name='shahira-backup-'+d.getFullYear()+'-'+('0'+(d.getMonth()+1)).slice(-2)+'-'+('0'+d.getDate()).slice(-2)+'.json';
  var txt=makeBackup(r.files),done=function(m){if(msg)msg.textContent=m};if(r.skipped){var w='⚠ المرفقات كبيرة (أكتر من 20 ميجا) فمش اتضمّنت في النسخة. ⚠ Attachments are over 20 MB so they are NOT in this backup.';if(msg)setTimeout(function(){msg.textContent+=' '+w},900);else alert(w)}
  try{var f=new File([txt],name,{type:'application/json'});
    if(navigator.canShare&&navigator.canShare({files:[f]})){navigator.share({files:[f],title:'shahira backup'}).then(function(){markBk();done('تمّ ✓ Done');if(cb)cb();else render()}).catch(function(){done('اتلغى Cancelled')});return}}catch(e){}
  var a=document.createElement('a');a.href=URL.createObjectURL(new Blob([txt],{type:'application/json'}));a.download=name;document.body.appendChild(a);a.click();setTimeout(function(){URL.revokeObjectURL(a.href);a.remove()},1500);
  markBk();done('الملف اتحفظ في تنزيلات الموبايل ✓ File saved to your Downloads ✓');if(cb)setTimeout(cb,600);else setTimeout(render,100);
}
function importBackup(file,msg,confirmFirst){
  var bad=function(){msg.textContent='ده مش ملف نسخة احتياطية صحيح. This is not a valid backup file.'};
  var r=new FileReader();r.onerror=bad;r.onload=function(){
    var o;try{o=JSON.parse(r.result)}catch(e){return bad()}
    if(!o||o.app!=='shahira'||!o.pin||!o.pin.s||!o.pin.h||!Array.isArray(o.companies)||!Array.isArray(o.items)||!Array.isArray(o.devs))return bad();
    if(confirmFirst&&!confirm('هيتبدل كل اللي على الموبايل ده بالنسخة دي، وكلمة السر هتبقى كلمة سر النسخة. Everything on this phone will be replaced by the backup, and the password becomes the backup\'s password. Continue?'))return;
    var fin=function(){save('sh.pin',o.pin);save('sh.companies',o.companies);save('sh.items',o.items);save('sh.devs',o.devs);save('sh.active',o.active||0);
    S.companies=o.companies;S.items=o.items;S.devs=o.devs;S.active=o.active||0;S.tab='work';
    showLock();setTimeout(function(){var e=$('#err');if(e){e.style.color='#1b5e2c';e.textContent='تمّ الاسترجاع ✓ اكتبي كلمة السر القديمة. Restored ✓ Enter your old password.'}},50)};
    var fl=o.files&&typeof o.files==='object'?o.files:null;
    if(!fl){fin();return}
    fClear().catch(function(){}).then(function(){return Promise.all(Object.keys(fl).map(function(k){var f=fl[k];return fPutBuf(+k,f.name,f.type,b64Buf(f.data)).catch(function(){})}))}).then(fin,fin)};
  r.readAsText(file)}
function backupPage(){return '<h1>نسخة احتياطية · Backup</h1><p>لو عايزة تنقلي التطبيق لموبايل تاني: احفظي نسخة هنا، وفي الموبايل الجديد افتحي التطبيق واختاري "استرجاع". كلمة السر والبيانات هيرجعوا زي ما هم.<br>To move to another phone: save a backup here, then on the new phone open the app and choose Restore. Your password and data come back the same.</p><div class="item"><div>آخر نسخة محفوظة Last backup: <b>'+fmtD(lastBk())+'</b></div><div>نسخة تلقائية داخل المتصفح In-browser auto copy: <b>'+fmtD(localStorage.getItem('sh.autoat'))+'</b></div></div>'+attInfo()+'<button class="btn pri" id="bk_save">💾 حفظ / مشاركة نسخة Save / Share backup</button><p class="muted">الملف فيه بياناتك مقروءة (كلمة السر مش مكتوبة فيه، بس مشفّرة). خليه عندك بس. The file holds your data in readable form (the password is not in it in plain text, only its hash). Keep it private.</p><p class="muted">التطبيق بيفكّرك كل يوم، ومبيقدرش يحفظ ملف لوحده وهو مقفول. كمان بيحتفظ بنسخة تلقائية جوه المتصفح (بتفيد لو مسحتي حاجة بالغلط، لكن مش لو اتمسحت بيانات المتصفح).<br>The app reminds you daily; a web page cannot save a file by itself while closed. It also keeps an automatic copy inside the browser (helps if you delete something by mistake, but not if browser data is cleared).</p><button class="btn" id="bk_auto">↩ رجّعي آخر نسخة تلقائية Restore last automatic copy</button><hr><button class="btn" id="bk_load">📂 استرجاع من نسخة Restore from a backup</button><input type="file" id="bk_file" accept=".json,application/json" hidden><p id="bk_msg" class="muted"></p>'}
/* ---- lock ---- */
async function showLock(){if(H.on&&H.pushed){H.pushed=false;H.skip++;try{history.back()}catch(e){H.skip--}}H.on=false;
  var rec=load('sh.pin',null);var first=!rec;
  $('#app').innerHTML=BRAND+'<div class="card"><h2>'+(first?'اختاري كلمة سر لتطبيقك<br>Choose your password':'أدخلي كلمة السر<br>Enter your password')+'</h2><p class="muted">'+(first?'كلمة السر بتتحفظ على موبايلك بس (مشفّرة) ومحدش يقدر يطّلع عليها. 4 أرقام أو أكتر.<br>Stored only on this phone, hashed. At least 4 characters. This is a simple lock, not strong security.':'')+'</p><input id="pin" type="password" inputmode="numeric" autocomplete="off" placeholder="كلمة السر Password">'+(first?'<input id="pin2" type="password" inputmode="numeric" autocomplete="off" placeholder="أعيدي كتابتها Repeat password">':'')+'<button class="btn pri" id="go">'+(first?'حفظ Save':'فتح Unlock')+'</button><p id="err" class="err"></p>'+(first?'':'<button class="btn ghost" id="forgot">نسيت كلمة السر؟ Forgot password</button>')+'</div>';
  if(first){var box=document.createElement('div');box.className='card';box.innerHTML='<p>عندك نسخة احتياطية من موبايل قديم؟<br>Have a backup from another phone?</p><button class="btn" id="rs_btn">📂 استرجاع نسخة Restore a backup</button><input type="file" id="rs_file" accept=".json,application/json" hidden><p id="rs_msg" class="err"></p>';$('#app').appendChild(box);$('#rs_btn').onclick=function(){$('#rs_file').click()};$('#rs_file').onchange=function(){if(this.files[0])importBackup(this.files[0],$('#rs_msg'),false)}}
  $('#go').onclick=async function(){
    var err=$('#err');err.textContent='';
    try{var raw=$('#pin').value;var p=normDigits(raw);
    if(first){if(p.length<4){err.textContent='قصيرة جداً Too short (4+)';return}if(p!==normDigits($('#pin2').value)){err.textContent='مش متطابقة Does not match';return}
      var salt=rndSalt();save('sh.pin',{s:b64(salt),h:await hashPin(p,salt)});start()}
    else{var h=await hashPin(p,unb64(rec.s));if(h!==rec.h&&raw!==p)h=(await hashPin(raw,unb64(rec.s)));if(h===rec.h)start();else err.textContent='كلمة السر غلط Wrong password'}}
    catch(e){err.textContent='حصل خطأ، جربي تاني Something went wrong, try again'}};
  var f=$('#forgot');if(f)f.onclick=function(){if(confirm('هيتمسح كل شيء على الموبايل ده! Everything on this phone will be erased. Continue?')){['sh.pin','sh.companies','sh.items','sh.active','sh.devs','sh.auto','sh.auto2','sh.autoat','sh.lastbk','sh.bksig'].forEach(function(k){localStorage.removeItem(k)});try{indexedDB.deleteDatabase('shahira-files')}catch(e){}S.companies=[];S.items=[];S.devs=[];S.active=0;showLock()}};
}
/* ---- main ---- */
var H={on:false,pushed:false,skip:0,init:false,atBase:false,tm:0};
var HOME=JSON.stringify(['work',false,0,false,0,false,false,false]);
function viewSig(){return JSON.stringify([S.tab,!!S.showItem,S.editItem||0,!!S.showDev,S.editDev||0,!!S.showCo,!!S.editCo,!!document.querySelector('.modal')])}
function resetView(){var m=document.querySelector('.modal');if(m)m.remove();S.tab='work';S.showItem=false;S.editItem=0;S.showDev=false;S.editDev=0;S.showCo=false;S.editCo=false}
function hist(){if(!H.on)return;var home=viewSig()===HOME;
  try{if(!home&&!H.pushed){H.atBase=false;clearTimeout(H.tm);history.pushState({sh:2},'');H.pushed=true}
  else if(home&&H.pushed){H.pushed=false;H.skip++;history.back()}}catch(e){}}
function toast(){var t=document.getElementById('exit_toast');if(t)t.remove();t=document.createElement('div');t.id='exit_toast';t.style.cssText='position:fixed;left:12px;right:12px;bottom:24px;background:#1b1340;color:#fff;border:3px solid #ffb300;border-radius:14px;padding:12px;text-align:center;font-weight:700;z-index:90';t.innerHTML='اضغطي رجوع مرة تانية للخروج<br>Press back again to exit';document.body.appendChild(t)}
function ensureSent(){if(H.init)return;if(navigator.userActivation&&!navigator.userActivation.isActive){var f=function(){document.removeEventListener('pointerdown',f,true);ensureSent()};document.addEventListener('pointerdown',f,true);return}
  H.init=true;try{history.replaceState({sh:0},'');history.pushState({sh:1},'')}catch(e){H.init=false}}
window.addEventListener('popstate',function(e){var idx=(e.state&&e.state.sh)||0;
  if(H.skip>0){H.skip--;if(idx===0&&H.on&&viewSig()===HOME){try{history.pushState({sh:1},'')}catch(x){}}return}
  if(!H.init)return;
  if(idx===1){H.atBase=false;clearTimeout(H.tm);var tt=document.getElementById('exit_toast');if(tt)tt.remove();if(H.on){H.pushed=false;if(viewSig()!==HOME){resetView();render()}}return}
  if(idx===0){var wasHome=!H.on||(viewSig()===HOME&&!H.pushed);H.pushed=false;
    if(H.on&&!wasHome){resetView();render();try{history.pushState({sh:1},'')}catch(x){}return}
    toast();H.atBase=true;clearTimeout(H.tm);H.tm=setTimeout(function(){var tt=document.getElementById('exit_toast');if(tt)tt.remove();if(H.atBase){H.atBase=false;try{history.forward()}catch(x){}}},2500)}});
function start(){autoCopy();H.on=true;H.pushed=false;S.tab='work';S.showItem=false;S.editItem=0;S.showDev=false;S.editDev=0;S.showCo=false;S.editCo=false;ensureSent();render()}
function render(){
  var tabs=[['work','شغلي My Work'],['devs','المطورين Developers'],['plan','الخطة Plan'],['practice','التمارين Practice'],['report','تقرير PDF Report'],['backup','نسخة احتياطية Backup']];
  var banner=(bkDue()&&!S.snooze&&(S.companies.length||S.items.length||S.devs.length))?'<div class="banner noprint"><b>⏰ وقت النسخة الاحتياطية Time for a backup</b><div>آخر نسخة Last backup: '+fmtD(lastBk())+'</div><button class="btn pri" id="bn_now">💾 احفظي نسخة دلوقتي Save backup now</button><button class="btn ghost" id="bn_later">بعدين Later</button></div>':'';
  var h=BRAND+banner+'<nav class="noprint">'+tabs.map(function(t){return '<button class="tab'+(S.tab===t[0]?' on':'')+'" data-tab="'+t[0]+'">'+t[1]+'</button>'}).join('')+'</nav>';
  h+=S.tab==='work'?work():S.tab==='plan'?plan():S.tab==='report'?report():S.tab==='devs'?devs():S.tab==='backup'?backupPage():practice();
  h+='<div class="foot noprint"><button class="btn ghost" id="lock">🔒 قفل Lock</button><button class="btn ghost" id="inst" hidden>⬇ تثبيت Install</button><p class="muted">'+iosHint()+'</p></div>';
  $('#app').innerHTML=h;wire();hist();
}
function iosHint(){var ios=/iphone|ipad/i.test(navigator.userAgent);var sa=window.matchMedia('(display-mode: standalone)').matches||navigator.standalone;if(sa)return '';return ios?'لتثبيت التطبيق: زر المشاركة ثم "إضافة إلى الشاشة الرئيسية". To install: Share, then Add to Home Screen.':'لتثبيت التطبيق: قائمة المتصفح ثم "تثبيت التطبيق" أو "إضافة إلى الشاشة الرئيسية". To install: browser menu, Install app.'}
function coName(id){var c=S.companies.filter(function(x){return x.id===id})[0];return c?c.name:''}
function work(){
  var co=S.companies.filter(function(c){return c.id===S.active})[0]||S.companies[0];
  var k=KINDS.filter(function(x){return x.v===S.kind})[0];
  var h='<h1>شغلي كل يوم · My Daily Work</h1>';
  var HK='<h3>شغلي My Work</h3><div class="row">'+KINDS.map(function(x){return '<button class="chip'+(x.v===S.kind?' on':'')+'" data-kind="'+x.v+'">'+x.l+'</button>'}).join('')+'</div>';
  h+='<h3>الشركات Companies</h3><div class="row">';
  S.companies.forEach(function(c){h+='<button class="chip'+(co&&co.id===c.id&&!S.showCo?' on':'')+'" data-co="'+c.id+'">'+esc(c.name)+'</button>'});
  h+='<button class="chip add" id="newco">＋ شركة Company</button></div>';
  var EC=S.editCo?co:null;if(S.showCo||S.editCo||!S.companies.length){h+='<div class="form"><input id="c_name" placeholder="اسم الشركة Company name" value="'+esc(EC&&EC.name)+'"><input id="c_addr" placeholder="العنوان Address" value="'+esc(EC&&EC.addr)+'"><input id="c_phone" inputmode="tel" placeholder="التليفون Phone" value="'+esc(EC&&EC.phone)+'"><input id="c_mgr" placeholder="اسم المدير Manager" value="'+esc(EC&&EC.mgr)+'"><input id="c_note" placeholder="تفاصيل أخرى Other details" value="'+esc(EC&&EC.note)+'"><button class="btn pri" id="saveco">حفظ Save</button>'+(S.companies.length?'<button class="btn ghost" id="cancelco">إلغاء Cancel</button>':'')+'</div>'}
  else if(co){h+='<div class="item"><b>'+esc(co.name)+'</b>'+(co.addr?'<div>'+esc(co.addr)+'</div>':'')+(co.phone?'<div dir="ltr">'+esc(co.phone)+'</div>':'')+(co.mgr?'<div>المدير Manager: '+esc(co.mgr)+'</div>':'')+(co.note?'<div>'+esc(co.note)+'</div>':'')+'<button class="btn" id="editco">تعديل Edit</button><button class="btn del" id="delco">حذف الشركة Delete company</button></div>'}
  h+=HK;
  var EI=S.editItem?S.items.filter(function(i){return i.id===S.editItem})[0]:null;
  if(!S.showItem&&!EI)h+='<button class="btn" id="newitem">＋ إضافة Add '+k.add+'</button>';
  else h+='<div class="form"><input id="i_title" placeholder="'+k.hint+'" value="'+esc(EI&&EI.title)+'">'+dateF(k.dl,'i_date',EI&&EI.date)+'<label>الساعة Time (9:30)<input id="i_time" inputmode="numeric" maxlength="5" placeholder="9:30" value="'+esc(EI&&EI.time)+'"></label><div class="row"><button class="chip'+((EI&&EI.ap==='PM')?'':' on')+'" data-ap="AM" id="ap_am">صباحاً AM</button><button class="chip'+((EI&&EI.ap==='PM')?' on':'')+'" data-ap="PM" id="ap_pm">مساءً PM</button></div>'+(S.companies.length?'<label>الشركة (اختياري) Company (optional)<select id="i_co"><option value="0">— بدون — None</option>'+S.companies.map(function(c){return '<option value="'+c.id+'"'+(EI&&EI.co===c.id?' selected':'')+'>'+esc(c.name)+'</option>'}).join('')+'</select></label>':'')+''+(S.kind==='docs'?attachUI(EI):'')+'<input id="i_note" placeholder="ملاحظة Note" value="'+esc(EI&&EI.note)+'"><button class="btn pri" id="saveitem">حفظ Save</button><button class="btn ghost" id="cancelitem">إلغاء Cancel</button></div>';
  var kitems=S.items.filter(function(i){return i.kind===S.kind});h+=sumLine(kitems.map(itemSt))+fltRow()+'<p class="muted noprint">زرار "تمّت" بيقفل البند ويفضل محفوظ تحت بلون رمادي، و"رجّعيها" بيرجّعه. Done keeps the item saved below in grey; Undo brings it back.</p>';
  var list=S.items.filter(function(i){return i.kind===S.kind&&fltOk(!!i.done)}).sort(function(a,b){return (a.done-b.done)||(a.date||'9').localeCompare(b.date||'9')||((a.ap==='PM')-(b.ap==='PM'))||(tmin(a)-tmin(b))});
  if(!list.length)h+='<p class="muted">'+k.empty+'</p>';
  list.forEach(function(i){var st=itemSt(i),cn=coName(i.co);h+='<div class="item is-'+st.k+(i.done?' done':'')+'"><b>'+(i.done?'✓ ':'')+esc(i.title)+'</b> '+stBadge(st)+(cn?'<div class="muted">🏢 '+esc(cn)+'</div>':'')+((i.date||i.time)?'<div dir="ltr">'+esc(i.date)+(i.time?' · '+esc(i.time)+' '+i.ap:'')+'</div>':'')+(i.note?'<div>'+esc(i.note)+'</div>':'')+(i.file?'<div class="item" style="background:#f3efff"><div>📎 <b dir="auto">'+esc(i.file.name)+'</b> <span class="muted" dir="ltr">('+fmtSize(i.file.size||0)+')</span></div><div class="row"><button class="btn" data-fopen="'+i.id+'">📂 فتح Open</button><button class="btn" data-fdl="'+i.id+'">⬇ تنزيل Download</button></div></div>':'')+'<div class="row"><button class="btn" data-done="'+i.id+'">'+(i.done?'رجّعيها Undo':'تمّت Done')+'</button><button class="btn" data-edit="'+i.id+'">تعديل Edit</button><button class="btn del" data-del="'+i.id+'">حذف Delete</button></div></div>'});
  return h;
}
function attachUI(EI){var cur=(EI&&EI.file&&!RMF)?EI.file:null;return '<div class="row"><button type="button" class="btn" id="i_att">📎 إرفاق ملف Attach file</button><input type="file" id="i_file" hidden accept=".pdf,.xls,.xlsx,.csv,.doc,.docx,.png,.jpg,.jpeg,.webp,application/pdf,image/*"></div><div class="muted" id="i_fname">'+(PF?'📎 '+esc(PF.name)+' ('+fmtSize(PF.size)+')':cur?'📎 '+esc(cur.name)+' ('+fmtSize(cur.size)+')':'لسه مفيش ملف No file yet')+'</div>'+((cur||PF)?'<button type="button" class="btn del" id="i_rm">إزالة الملف Remove file</button>':'')+'<p class="muted">الحد الأقصى 10 ميجا للملف. الملف بيتحفظ على موبايلك بس، من غير تشفير. Max 10 MB per file. Stored only on this phone, not encrypted.</p>'}
function attInfo(){var t=filesTotal();if(!t.n)return '';return '<div class="item">📎 المرفقات Attachments: <b>'+t.n+'</b> · <b dir="ltr">'+fmtSize(t.size)+'</b><br><span class="muted">بتتضمّن في ملف النسخة الاحتياطية (الملف بيكبر). لو المرفقات أكتر من 20 ميجا مش هتتضمّن. Included in the backup file (it gets bigger). Not included if over 20 MB in total.</span></div>'}
function dateF(label,id,val){return '<label>'+label+'<input id="'+id+'" type="date" value="'+esc(val)+'"></label><div class="row"><button type="button" class="chip" data-pick="'+id+'">📅 اختاري اليوم Pick a day</button><button type="button" class="chip" data-clr="'+id+'">✕ مسح Clear</button></div><div class="muted" id="'+id+'_show" dir="ltr">'+(val?esc(val):'لسه ما اتحددش · Not set')+'</div>'}
function dShow(id){var i=$('#'+id),t=$('#'+id+'_show');if(i&&t)t.textContent=i.value||'لسه ما اتحددش · Not set'}
function tmin(i){var m=/^(\d{1,2}):?(\d{2})?$/.exec(i.time||'');if(!m)return 0;return (+m[1]%12)*60+(+m[2]||0)}
var DF=[['signed','تم الامضاء Signed'],['contacted','تم التواصل Contacted'],['oriented','حضور واورينتيشن في الشركة Attended + orientation done']];
function devs(){
  var h='<h1>شركات المطورين · Developer Companies</h1>'+sumLine(S.devs.map(devSt))+fltRow();
  var ED=S.editDev?S.devs.filter(function(d){return d.id===S.editDev})[0]:null;
  if(!S.showDev&&!ED)h+='<button class="btn" id="newdev">＋ إضافة مطوّر Add developer</button>';
  else h+='<div class="form"><input id="d_name" placeholder="اسم شركة المطوّر Developer name" value="'+esc(ED&&ED.name)+'"><input id="d_contact" placeholder="جهة الاتصال / تليفون Contact / phone" value="'+esc(ED&&ED.contact)+'"><input id="d_note" placeholder="المشروعات / ملاحظة Projects / note" value="'+esc(ED&&ED.note)+'">'+dateF('موعد التواصل المخطط Planned contact day','d_pdate',ED&&ED.pdate)+'<label>الساعة Time (9:30)<input id="d_ptime" inputmode="numeric" maxlength="5" placeholder="9:30" value="'+esc(ED&&ED.ptime)+'"></label><div class="row"><button class="chip'+((ED&&ED.pap==='PM')?'':' on')+'" data-dap="AM">صباحاً AM</button><button class="chip'+((ED&&ED.pap==='PM')?' on':'')+'" data-dap="PM">مساءً PM</button></div><div class="row"><button class="chip'+((ED&&!ED.deal)?'':' on')+'" data-dd="1" id="dd_y">نتعامل معاهم We deal</button><button class="chip'+((ED&&!ED.deal)?' on':'')+'" data-dd="0" id="dd_n">لا نتعامل No</button></div><button class="btn pri" id="savedev">حفظ Save</button><button class="btn ghost" id="canceldev">إلغاء Cancel</button></div>';
  var l=S.devs.filter(function(d){return fltOk(!!d.contacted)}).sort(function(a,b){return (!!a.contacted-!!b.contacted)||(a.pdate||'9').localeCompare(b.pdate||'9')});
  if(!l.length)h+='<p class="muted">مفيش مطورين لسه. No developers yet.</p>';
  l.forEach(function(d){var st=devSt(d);h+='<div class="item is-'+st.k+(d.deal?' deal':'')+'"><b>'+esc(d.name)+'</b> '+(st.k==='none'?'':stBadge(st))+(d.contact?'<div dir="ltr">'+esc(d.contact)+'</div>':'')+(d.note?'<div>'+esc(d.note)+'</div>':'')+((d.pdate||d.ptime)?'<div class="plan" dir="ltr">موعد التواصل Planned contact: '+esc(d.pdate)+(d.ptime?' · '+esc(d.ptime)+' '+(d.pap||'AM'):'')+'</div>':'')+'<div class="row">'+DF.map(function(f){return '<button class="chip'+(d[f[0]]?' on':'')+'" data-df="'+f[0]+':'+d.id+'">'+(d[f[0]]?'✓ ':'○ ')+f[1]+'</button>'}).join('')+'</div><div class="row"><button class="chip'+(d.deal?' on':'')+'" data-dtog="'+d.id+'">'+(d.deal?'✓ نتعامل معاهم We deal with them (اختياري optional)':'✗ لا نتعامل No deal (اختياري optional)')+'</button><button class="btn" data-dedit="'+d.id+'">تعديل Edit</button><button class="btn del" data-ddel="'+d.id+'">حذف Delete</button></div></div>'});
  return h}
function report(){
  var h='<h1>تقرير شغلي · My Work Report</h1><p class="muted">'+new Date().toLocaleDateString()+'</p><button class="btn pri noprint" id="doprint">🖨 طباعة / حفظ PDF Print / Save as PDF</button><p class="muted noprint">في نافذة الطباعة اختاري "حفظ كـ PDF". In the print window choose Save as PDF.</p>';
  if(!S.companies.length&&!S.items.length&&!S.devs.length)return h+'<p>مفيش بيانات. No data yet.</p>';
  var dl=S.devs;if(dl.length){h+='<h3>شركات المطورين Developers</h3><table><tr><th>المطوّر Developer</th><th>الاتصال Contact</th><th>ملاحظة Note</th><th>موعد التواصل Planned contact</th><th>الامضاء Signed</th><th>التواصل Contacted</th><th>حضور + اورينتيشن Attended + Orientation</th><th>الحالة Status</th><th>حالة الموعد Contact status</th></tr>';dl.forEach(function(d){h+='<tr><td>'+esc(d.name)+'</td><td dir="ltr">'+esc(d.contact)+'</td><td>'+esc(d.note)+'</td><td dir="ltr">'+esc(d.pdate)+(d.ptime?' '+esc(d.ptime)+' '+(d.pap||'AM'):'')+'</td><td>'+(d.signed?'✓ نعم Yes':'✗ لا No')+'</td><td>'+(d.contacted?'✓ نعم Yes':'✗ لا No')+'</td><td>'+(d.oriented?'✓ نعم Yes':'✗ لا No')+'</td><td>'+(d.deal?'نتعامل We deal':'لا نتعامل No deal')+'</td><td>'+esc(stText(devSt(d)))+'</td></tr>'});h+='</table>'}
    KINDS.forEach(function(k){var l=S.items.filter(function(i){return i.kind===k.v});if(!l.length)return;h+='<h3>'+k.l+'</h3><table><tr><th>البند Item</th><th>الشركة Company</th><th>التاريخ Date</th><th>الساعة Time</th><th>ملاحظة Note</th><th>تمّت Done</th><th>الحالة Status</th></tr>';
      l.sort(function(a,b){return (a.date||'9').localeCompare(b.date||'9')||((a.ap==='PM')-(b.ap==='PM'))||(tmin(a)-tmin(b))}).forEach(function(i){h+='<tr><td>'+esc(i.title)+'</td><td>'+esc(coName(i.co))+'</td><td dir="ltr">'+esc(i.date)+'</td><td dir="ltr">'+(i.time?esc(i.time)+' '+i.ap:'')+'</td><td>'+esc(i.note)+'</td><td>'+(i.done?'✓':'')+'</td><td>'+esc(stText(itemSt(i)))+'</td></tr>'});h+='</table>'});
    if(S.companies.length){h+='<h3>الشركات Companies</h3>';S.companies.forEach(function(c){h+='<div><b>'+esc(c.name)+'</b>'+(c.addr?' · '+esc(c.addr):'')+(c.phone?' · <span dir="ltr">'+esc(c.phone)+'</span>':'')+(c.mgr?' · المدير Manager: '+esc(c.mgr):'')+(c.note?' · '+esc(c.note):'')+'</div>'})}
  return h}
function plan(){var h='<h1>خطتك لشغل الأوبريشن والسكرتارية<br>Your 6-week plan</h1><h3>الروتين اليومي Daily routine</h3>';daily.forEach(function(d,i){h+='<div class="item"><b>'+(i+1)+'. '+d.name+'</b><div>'+d.detail+'</div></div>'});weeks.forEach(function(w){h+='<h3>الأسبوع '+w.n+' · Week '+w.n+': '+w.title+'</h3><p>'+w.goal+'</p><ul>'+w.items.map(function(x){return '<li>'+x+'</li>'}).join('')+'</ul>'});return h}
function practice(){var h='<h1>تمارين عملية<br>Practice exercises</h1>';topics.forEach(function(t){h+='<h3>'+t.label+': '+t.title+'</h3><p>'+t.intro+'</p><ul>'+t.items.map(function(x){return '<li>'+x+'</li>'}).join('')+'</ul>'});return h+'<p class="muted">الأسماء والأرقام وهمية. Use fake data for practice.</p>'}
function wire(){
  document.querySelectorAll('[data-tab]').forEach(function(b){b.onclick=function(){S.tab=b.dataset.tab;render()}});
  document.querySelectorAll('[data-co]').forEach(function(b){b.onclick=function(){S.active=+b.dataset.co;S.showCo=false;save('sh.active',S.active);render()}});
  document.querySelectorAll('[data-kind]').forEach(function(b){b.onclick=function(){S.kind=b.dataset.kind;S.showItem=false;render()}});
  document.querySelectorAll('[data-pick]').forEach(function(b){var id=b.dataset.pick;b.onclick=function(){var i=$('#'+id);try{if(i.showPicker)i.showPicker();else{i.focus();i.click()}}catch(e){try{i.focus();i.click()}catch(e2){}}}});
  document.querySelectorAll('[data-clr]').forEach(function(b){var id=b.dataset.clr;b.onclick=function(){var i=$('#'+id);i.value='';dShow(id)}});
  ['i_date','d_pdate'].forEach(function(id){var i=$('#'+id);if(i){i.onchange=function(){dShow(id)};i.oninput=function(){dShow(id)}}});
  document.querySelectorAll('[data-fopen]').forEach(function(b){b.onclick=function(){openFile(+b.dataset.fopen,false)}});
  document.querySelectorAll('[data-fdl]').forEach(function(b){b.onclick=function(){openFile(+b.dataset.fdl,true)}});
  var fi=$('#i_file');if(fi){$('#i_att').onclick=function(){fi.click()};fi.onchange=function(){var f=this.files&&this.files[0];if(!f)return;if(f.size>MAXF){alert('الملف كبير (أكتر من 10 ميجا). اختاري ملف أصغر.\nFile is too big (over 10 MB). Please choose a smaller file.');this.value='';return}PF=f;RMF=false;$('#i_fname').textContent='📎 '+f.name+' ('+fmtSize(f.size)+')'}}
  var rmb=$('#i_rm');if(rmb)rmb.onclick=function(){PF=null;RMF=true;$('#i_fname').textContent='لسه مفيش ملف No file yet';rmb.hidden=true};
  document.querySelectorAll('[data-flt]').forEach(function(b){b.onclick=function(){S.filter=b.dataset.flt;render()}});
  var v=function(id){return $('#'+id).value.trim()};
  var on=function(id,f){var e=$('#'+id);if(e)e.onclick=f};
  on('newco',function(){S.showCo=true;S.editCo=false;render()});on('cancelco',function(){S.showCo=false;S.editCo=false;render()});on('editco',function(){S.editCo=true;S.showCo=false;render();window.scrollTo(0,0)});
  on('saveco',function(){if(!v('c_name'))return;if(S.editCo){var cur=S.companies.filter(function(c){return c.id===S.active})[0]||S.companies[0];if(!cur){S.editCo=false;render();return}cur.name=v('c_name');cur.addr=v('c_addr');cur.phone=v('c_phone');cur.mgr=v('c_mgr');cur.note=v('c_note');S.editCo=false;save('sh.companies',S.companies);render();return}var c={id:Date.now(),name:v('c_name'),addr:v('c_addr'),phone:v('c_phone'),mgr:v('c_mgr'),note:v('c_note')};S.companies.push(c);S.active=c.id;S.showCo=false;save('sh.companies',S.companies);save('sh.active',c.id);render()});
  on('delco',function(){if(!confirm('حذف الشركة؟ شغلك مش هيتمسح. Delete this company? Your work items stay.'))return;var id=(S.companies.filter(function(c){return c.id===S.active})[0]||S.companies[0]).id;S.companies=S.companies.filter(function(c){return c.id!==id});S.items.forEach(function(i){if(i.co===id)i.co=0});S.devs.forEach(function(d){if(d.co===id)d.co=0});save('sh.devs',S.devs);S.active=0;save('sh.active',0);save('sh.companies',S.companies);save('sh.items',S.items);render()});
  on('newitem',function(){PF=null;RMF=false;S.showItem=true;render()});on('cancelitem',function(){PF=null;RMF=false;S.showItem=false;S.editItem=0;render()});document.querySelectorAll('[data-edit]').forEach(function(b){b.onclick=function(){PF=null;RMF=false;S.editItem=+b.dataset.edit;S.showItem=false;render();window.scrollTo(0,0)}});
  var EIw=S.editItem?S.items.filter(function(i){return i.id===S.editItem})[0]:null;var ap=(EIw&&EIw.ap)||'AM';document.querySelectorAll('[data-ap]').forEach(function(b){b.onclick=function(){ap=b.dataset.ap;document.querySelectorAll('[data-ap]').forEach(function(x){x.classList.toggle('on',x===b)})}});
  on('saveitem',async function(){if(!v('i_title'))return;var coV=+(($('#i_co')||{}).value||0),id=S.editItem||Date.now(),meta;
    try{if(PF){await fPut(id,PF);meta={name:PF.name,type:PF.type||'',size:PF.size}}else if(RMF&&S.editItem){await fDel(id);meta=null}}catch(e){alert('تعذر حفظ الملف، يمكن المساحة ممتلئة؟\nCould not store the file. Is storage full?');return}
    if(S.editItem){S.items.forEach(function(i){if(i.id===S.editItem){i.title=v('i_title');i.date=v('i_date');i.time=v('i_time');i.ap=ap;i.note=v('i_note');i.co=coV;if(meta!==undefined){if(meta)i.file=meta;else delete i.file}}});S.editItem=0}
    else{var it={id:id,co:coV,kind:S.kind,title:v('i_title'),date:v('i_date'),time:v('i_time'),ap:ap,note:v('i_note'),done:false};if(meta)it.file=meta;S.items.push(it);S.showItem=false}
    PF=null;RMF=false;save('sh.items',S.items);render()});
  document.querySelectorAll('[data-done]').forEach(function(b){b.onclick=function(){S.items.forEach(function(i){if(i.id==b.dataset.done)i.done=!i.done});save('sh.items',S.items);render()}});
  document.querySelectorAll('[data-del]').forEach(function(b){b.onclick=function(){var did=b.dataset.del;if(S.items.some(function(i){return i.id==did&&i.file})){if(!confirm('الملف المرفق هيتمسح كمان. The attached file will be deleted too. Continue?'))return;fDel(+did).catch(function(){})}S.items=S.items.filter(function(i){return i.id!=did});save('sh.items',S.items);render()}});
  on('newdev',function(){S.showDev=true;render()});on('canceldev',function(){S.showDev=false;S.editDev=0;render()});document.querySelectorAll('[data-dedit]').forEach(function(b){b.onclick=function(){S.editDev=+b.dataset.dedit;S.showDev=false;render();window.scrollTo(0,0)}});
  var EDw=S.editDev?S.devs.filter(function(d){return d.id===S.editDev})[0]:null;var dd=EDw?!!EDw.deal:true;var dap=(EDw&&EDw.pap)||'AM';document.querySelectorAll('[data-dap]').forEach(function(b){b.onclick=function(){dap=b.dataset.dap;document.querySelectorAll('[data-dap]').forEach(function(x){x.classList.toggle('on',x===b)})}});document.querySelectorAll('[data-dd]').forEach(function(b){b.onclick=function(){dd=b.dataset.dd==='1';document.querySelectorAll('[data-dd]').forEach(function(x){x.classList.toggle('on',x===b)})}});
  on('savedev',function(){if(!v('d_name'))return;if(S.editDev){S.devs.forEach(function(d){if(d.id===S.editDev){d.name=v('d_name');d.contact=v('d_contact');d.note=v('d_note');d.pdate=v('d_pdate');d.ptime=v('d_ptime');d.pap=dap;d.deal=dd}});S.editDev=0;save('sh.devs',S.devs);render();return}S.devs.push({id:Date.now(),co:0,name:v('d_name'),contact:v('d_contact'),note:v('d_note'),pdate:v('d_pdate'),ptime:v('d_ptime'),pap:dap,deal:dd,signed:false,contacted:false,oriented:false});S.showDev=false;save('sh.devs',S.devs);render()});
  document.querySelectorAll('[data-df]').forEach(function(b){b.onclick=function(){var a=b.dataset.df.split(':');S.devs.forEach(function(d){if(d.id==a[1])d[a[0]]=!d[a[0]]});save('sh.devs',S.devs);render()}});
  document.querySelectorAll('[data-dtog]').forEach(function(b){b.onclick=function(){S.devs.forEach(function(d){if(d.id==b.dataset.dtog)d.deal=!d.deal});save('sh.devs',S.devs);render()}});
  document.querySelectorAll('[data-ddel]').forEach(function(b){b.onclick=function(){if(!confirm('حذف شركة المطوّر ده؟ Delete this developer company?'))return;S.devs=S.devs.filter(function(d){return d.id!=b.dataset.ddel});save('sh.devs',S.devs);render()}});
  on('bn_now',function(){exportBackup(null)});on('bn_later',function(){S.snooze=true;render()});on('bk_auto',function(){restoreAuto($('#bk_msg'))});
  on('bk_save',function(){exportBackup($('#bk_msg'))});on('bk_load',function(){$('#bk_file').click()});var bf=$('#bk_file');if(bf)bf.onchange=function(){if(this.files[0])importBackup(this.files[0],$('#bk_msg'),true)};
  on('lock',askLock);on('doprint',function(){window.print()});
  if(window.__ip){var e=$('#inst');e.hidden=false;e.onclick=function(){window.__ip.prompt()}}
}
window.addEventListener('beforeinstallprompt',function(e){e.preventDefault();window.__ip=e;var b=$('#inst');if(b){b.hidden=false;b.onclick=function(){e.prompt()}}});
if('serviceWorker'in navigator)navigator.serviceWorker.register('sw.js').then(function(r){try{r.update().catch(function(){})}catch(e){}},function(){});
window.addEventListener('error',function(ev){var d=document.createElement('div');d.style.cssText='position:fixed;left:0;right:0;bottom:0;background:#b00020;color:#fff;padding:8px;font-size:12px;z-index:99;direction:ltr';d.textContent='Error: '+(ev.message||'')+' ('+(ev.lineno||'')+') v7';document.body.appendChild(d)});
var vf=document.createElement('div');vf.style.cssText='text-align:center;font-size:11px;color:#6b5b8a;padding:6px';vf.textContent='shahira v7';document.body.appendChild(vf);
showLock();
