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
async function hashPin(pin,salt){var k=await crypto.subtle.importKey('raw',enc.encode(pin),'PBKDF2',false,['deriveBits']);return b64(await crypto.subtle.deriveBits({name:'PBKDF2',salt:salt,iterations:150000,hash:'SHA-256'},k,256))}
function load(k,d){try{var v=localStorage.getItem(k);return v?JSON.parse(v):d}catch(e){return d}}
function save(k,v){try{localStorage.setItem(k,JSON.stringify(v));return true}catch(e){alert('تعذر الحفظ Could not save');return false}}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
var S={tab:'work',kind:'tasks',showCo:false,showItem:false,companies:load('sh.companies',[]),items:load('sh.items',[]),devs:load('sh.devs',[]),showDev:false,editDev:0,editItem:0,editCo:false,active:load('sh.active',0)};
var BRAND='<div class="brand noprint"><svg viewBox="0 0 320 110" width="100%" height="110" aria-hidden="true"><defs><linearGradient id="g1" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#ff6fa8"/><stop offset="1" stop-color="#ffb84d"/></linearGradient><linearGradient id="g2" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#4dd0e1"/><stop offset="1" stop-color="#9b6bff"/></linearGradient></defs><g transform="translate(232 8) rotate(12 40 40)"><path d="M40 40 C 10 -8, -14 20, 8 42 C -6 56, 16 80, 40 48 Z" fill="url(#g1)" stroke="#d6336c" stroke-width="2.5" stroke-linejoin="round"/><path d="M40 40 C 70 -8, 94 20, 72 42 C 86 56, 64 80, 40 48 Z" fill="url(#g2)" stroke="#6741d9" stroke-width="2.5" stroke-linejoin="round"/><circle cx="20" cy="30" r="5" fill="#fff" opacity=".8"/><circle cx="60" cy="30" r="5" fill="#fff" opacity=".8"/><path d="M40 30 L40 62" stroke="#3b2a50" stroke-width="5" stroke-linecap="round"/><path d="M40 30 C 36 16, 28 12, 26 8 M40 30 C 44 16, 52 12, 54 8" stroke="#3b2a50" stroke-width="2" fill="none" stroke-linecap="round"/></g><text x="8" y="78" textLength="212" lengthAdjust="spacingAndGlyphs" class="bn" fill="#e8590c" stroke="#862e9c" stroke-width="1">shahira</text><path d="M10 92 C 60 100, 120 86, 200 94" stroke="#20c997" stroke-width="4" fill="none" stroke-linecap="round" stroke-dasharray="2 8"/></svg></div>';
/* ---- lock ---- */
async function showLock(){
  var rec=load('sh.pin',null);var first=!rec;
  $('#app').innerHTML=BRAND+'<div class="card"><h2>'+(first?'اختاري كلمة سر لتطبيقك<br>Choose your password':'أدخلي كلمة السر<br>Enter your password')+'</h2><p class="muted">'+(first?'كلمة السر بتتحفظ على موبايلك بس (مشفّرة) ومحدش يقدر يطّلع عليها. 4 أرقام أو أكتر.<br>Stored only on this phone, hashed. At least 4 characters. This is a simple lock, not strong security.':'')+'</p><input id="pin" type="password" inputmode="numeric" autocomplete="off" placeholder="كلمة السر Password">'+(first?'<input id="pin2" type="password" inputmode="numeric" autocomplete="off" placeholder="أعيدي كتابتها Repeat password">':'')+'<button class="btn pri" id="go">'+(first?'حفظ Save':'فتح Unlock')+'</button><p id="err" class="err"></p>'+(first?'':'<button class="btn ghost" id="forgot">نسيت كلمة السر؟ Forgot password</button>')+'</div>';
  $('#go').onclick=async function(){
    var p=$('#pin').value;var err=$('#err');
    if(first){if(p.length<4){err.textContent='قصيرة جداً Too short (4+)';return}if(p!==$('#pin2').value){err.textContent='مش متطابقة Does not match';return}
      var salt=crypto.getRandomValues(new Uint8Array(16));save('sh.pin',{s:b64(salt),h:await hashPin(p,salt)});start()}
    else{var h=await hashPin(p,unb64(rec.s));if(h===rec.h)start();else err.textContent='كلمة السر غلط Wrong password'}};
  var f=$('#forgot');if(f)f.onclick=function(){if(confirm('هيتمسح كل شيء على الموبايل ده! Everything on this phone will be erased. Continue?')){['sh.pin','sh.companies','sh.items','sh.active','sh.devs'].forEach(function(k){localStorage.removeItem(k)});S.companies=[];S.items=[];S.devs=[];S.active=0;showLock()}};
}
/* ---- main ---- */
function start(){render()}
function render(){
  var tabs=[['work','شغلي My Work'],['devs','المطورين Developers'],['plan','الخطة Plan'],['practice','التمارين Practice'],['report','تقرير PDF Report']];
  var h=BRAND+'<nav class="noprint">'+tabs.map(function(t){return '<button class="tab'+(S.tab===t[0]?' on':'')+'" data-tab="'+t[0]+'">'+t[1]+'</button>'}).join('')+'</nav>';
  h+=S.tab==='work'?work():S.tab==='plan'?plan():S.tab==='report'?report():S.tab==='devs'?devs():practice();
  h+='<div class="foot noprint"><button class="btn ghost" id="lock">🔒 قفل Lock</button><button class="btn ghost" id="inst" hidden>⬇ تثبيت Install</button><p class="muted">'+iosHint()+'</p></div>';
  $('#app').innerHTML=h;wire();
}
function iosHint(){var ios=/iphone|ipad/i.test(navigator.userAgent);var sa=window.matchMedia('(display-mode: standalone)').matches||navigator.standalone;if(sa)return '';return ios?'لتثبيت التطبيق: زر المشاركة ثم "إضافة إلى الشاشة الرئيسية". To install: Share, then Add to Home Screen.':'لتثبيت التطبيق: قائمة المتصفح ثم "تثبيت التطبيق" أو "إضافة إلى الشاشة الرئيسية". To install: browser menu, Install app.'}
function work(){
  var co=S.companies.filter(function(c){return c.id===S.active})[0]||S.companies[0];
  var k=KINDS.filter(function(x){return x.v===S.kind})[0];
  var h='<h1>شغلي كل يوم · My Daily Work</h1><h3>الشركات Companies</h3><div class="row">';
  S.companies.forEach(function(c){h+='<button class="chip'+(co&&co.id===c.id&&!S.showCo?' on':'')+'" data-co="'+c.id+'">'+esc(c.name)+'</button>'});
  h+='<button class="chip add" id="newco">＋ شركة Company</button></div>';
  var EC=S.editCo?co:null;if(S.showCo||S.editCo||!S.companies.length){h+='<div class="form"><input id="c_name" placeholder="اسم الشركة Company name" value="'+esc(EC&&EC.name)+'"><input id="c_addr" placeholder="العنوان Address" value="'+esc(EC&&EC.addr)+'"><input id="c_phone" inputmode="tel" placeholder="التليفون Phone" value="'+esc(EC&&EC.phone)+'"><input id="c_mgr" placeholder="اسم المدير Manager" value="'+esc(EC&&EC.mgr)+'"><input id="c_note" placeholder="تفاصيل أخرى Other details" value="'+esc(EC&&EC.note)+'"><button class="btn pri" id="saveco">حفظ Save</button>'+(S.companies.length?'<button class="btn ghost" id="cancelco">إلغاء Cancel</button>':'')+'</div>'}
  if(!co)return h;
  if(!S.showCo&&!S.editCo){h+='<div class="item"><b>'+esc(co.name)+'</b>'+(co.addr?'<div>'+esc(co.addr)+'</div>':'')+(co.phone?'<div dir="ltr">'+esc(co.phone)+'</div>':'')+(co.mgr?'<div>المدير Manager: '+esc(co.mgr)+'</div>':'')+(co.note?'<div>'+esc(co.note)+'</div>':'')+'<button class="btn" id="editco">تعديل Edit</button><button class="btn del" id="delco">حذف الشركة Delete company</button></div>'}
  h+='<h3>'+esc(co.name)+' · شغلي My Work</h3><div class="row">'+KINDS.map(function(x){return '<button class="chip'+(x.v===S.kind?' on':'')+'" data-kind="'+x.v+'">'+x.l+'</button>'}).join('')+'</div>';
  var EI=S.editItem?S.items.filter(function(i){return i.id===S.editItem})[0]:null;
  if(!S.showItem&&!EI)h+='<button class="btn" id="newitem">＋ إضافة Add '+k.add+'</button>';
  else h+='<div class="form"><input id="i_title" placeholder="'+k.hint+'" value="'+esc(EI&&EI.title)+'"><label>'+k.dl+'<input id="i_date" type="date" value="'+esc(EI&&EI.date)+'"></label><label>الساعة Time (9:30)<input id="i_time" inputmode="numeric" maxlength="5" placeholder="9:30" value="'+esc(EI&&EI.time)+'"></label><div class="row"><button class="chip'+((EI&&EI.ap==='PM')?'':' on')+'" data-ap="AM" id="ap_am">صباحاً AM</button><button class="chip'+((EI&&EI.ap==='PM')?' on':'')+'" data-ap="PM" id="ap_pm">مساءً PM</button></div><input id="i_note" placeholder="ملاحظة Note" value="'+esc(EI&&EI.note)+'"><button class="btn pri" id="saveitem">حفظ Save</button><button class="btn ghost" id="cancelitem">إلغاء Cancel</button></div>';
  var list=S.items.filter(function(i){return i.co===co.id&&i.kind===S.kind}).sort(function(a,b){return (a.done-b.done)||(a.date||'9').localeCompare(b.date||'9')||((a.ap==='PM')-(b.ap==='PM'))||(tmin(a)-tmin(b))});
  if(!list.length)h+='<p class="muted">'+k.empty+'</p>';
  list.forEach(function(i){h+='<div class="item'+(i.done?' done':'')+'"><b>'+esc(i.title)+'</b>'+((i.date||i.time)?'<div dir="ltr">'+esc(i.date)+(i.time?' · '+esc(i.time)+' '+i.ap:'')+'</div>':'')+(i.note?'<div>'+esc(i.note)+'</div>':'')+'<div class="row"><button class="btn" data-done="'+i.id+'">'+(i.done?'رجّعيها Undo':'تمّت Done')+'</button><button class="btn" data-edit="'+i.id+'">تعديل Edit</button><button class="btn del" data-del="'+i.id+'">حذف Delete</button></div></div>'});
  return h;
}
function tmin(i){var m=/^(\d{1,2}):?(\d{2})?$/.exec(i.time||'');if(!m)return 0;return (+m[1]%12)*60+(+m[2]||0)}
var DF=[['signed','تم الامضاء Signed'],['contacted','تم التواصل Contacted'],['oriented','حضور واورينتيشن في الشركة Attended + orientation done']];
function devs(){
  var co=S.companies.filter(function(c){return c.id===S.active})[0]||S.companies[0];
  var h='<h1>شركات المطورين · Developer Companies</h1>';
  if(!co)return h+'<p>ضيفي شركتك الأول من تبويب شغلي. Add your company first in the My Work tab.</p>';
  h+='<p class="muted">'+esc(co.name)+'</p>';
  var ED=S.editDev?S.devs.filter(function(d){return d.id===S.editDev})[0]:null;
  if(!S.showDev&&!ED)h+='<button class="btn" id="newdev">＋ إضافة مطوّر Add developer</button>';
  else h+='<div class="form"><input id="d_name" placeholder="اسم شركة المطوّر Developer name" value="'+esc(ED&&ED.name)+'"><input id="d_contact" placeholder="جهة الاتصال / تليفون Contact / phone" value="'+esc(ED&&ED.contact)+'"><input id="d_note" placeholder="المشروعات / ملاحظة Projects / note" value="'+esc(ED&&ED.note)+'"><label>موعد التواصل المخطط Planned contact day<input id="d_pdate" type="date" value="'+esc(ED&&ED.pdate)+'"></label><label>الساعة Time (9:30)<input id="d_ptime" inputmode="numeric" maxlength="5" placeholder="9:30" value="'+esc(ED&&ED.ptime)+'"></label><div class="row"><button class="chip'+((ED&&ED.pap==='PM')?'':' on')+'" data-dap="AM">صباحاً AM</button><button class="chip'+((ED&&ED.pap==='PM')?' on':'')+'" data-dap="PM">مساءً PM</button></div><div class="row"><button class="chip'+((ED&&!ED.deal)?'':' on')+'" data-dd="1" id="dd_y">نتعامل معاهم We deal</button><button class="chip'+((ED&&!ED.deal)?' on':'')+'" data-dd="0" id="dd_n">لا نتعامل No</button></div><button class="btn pri" id="savedev">حفظ Save</button><button class="btn ghost" id="canceldev">إلغاء Cancel</button></div>';
  var l=S.devs.filter(function(d){return d.co===co.id});
  if(!l.length)h+='<p class="muted">مفيش مطورين لسه. No developers yet.</p>';
  l.forEach(function(d){h+='<div class="item'+(d.deal?' deal':'')+'"><b>'+esc(d.name)+'</b>'+(d.contact?'<div dir="ltr">'+esc(d.contact)+'</div>':'')+(d.note?'<div>'+esc(d.note)+'</div>':'')+((d.pdate||d.ptime)?'<div class="plan" dir="ltr">موعد التواصل Planned contact: '+esc(d.pdate)+(d.ptime?' · '+esc(d.ptime)+' '+(d.pap||'AM'):'')+'</div>':'')+'<div class="row">'+DF.map(function(f){return '<button class="chip'+(d[f[0]]?' on':'')+'" data-df="'+f[0]+':'+d.id+'">'+(d[f[0]]?'✓ ':'○ ')+f[1]+'</button>'}).join('')+'</div><div class="row"><button class="chip'+(d.deal?' on':'')+'" data-dtog="'+d.id+'">'+(d.deal?'✓ نتعامل معاهم We deal with them (اختياري optional)':'✗ لا نتعامل No deal (اختياري optional)')+'</button><button class="btn" data-dedit="'+d.id+'">تعديل Edit</button><button class="btn del" data-ddel="'+d.id+'">حذف Delete</button></div></div>'});
  return h}
function report(){
  var h='<h1>تقرير شغلي · My Work Report</h1><p class="muted">'+new Date().toLocaleDateString()+'</p><button class="btn pri noprint" id="doprint">🖨 طباعة / حفظ PDF Print / Save as PDF</button><p class="muted noprint">في نافذة الطباعة اختاري "حفظ كـ PDF". In the print window choose Save as PDF.</p>';
  if(!S.companies.length)return h+'<p>مفيش بيانات. No data yet.</p>';
  S.companies.forEach(function(c){h+='<h2>'+esc(c.name)+'</h2>'+(c.addr?'<div>'+esc(c.addr)+'</div>':'')+(c.phone?'<div dir="ltr">'+esc(c.phone)+'</div>':'')+(c.mgr?'<div>المدير Manager: '+esc(c.mgr)+'</div>':'')+(c.note?'<div>'+esc(c.note)+'</div>':'');
    var dl=S.devs.filter(function(d){return d.co===c.id});if(dl.length){h+='<h3>شركات المطورين Developers</h3><table><tr><th>المطوّر Developer</th><th>الاتصال Contact</th><th>ملاحظة Note</th><th>موعد التواصل Planned contact</th><th>الامضاء Signed</th><th>التواصل Contacted</th><th>حضور + اورينتيشن Attended + Orientation</th><th>الحالة Status</th></tr>';dl.forEach(function(d){h+='<tr><td>'+esc(d.name)+'</td><td dir="ltr">'+esc(d.contact)+'</td><td>'+esc(d.note)+'</td><td dir="ltr">'+esc(d.pdate)+(d.ptime?' '+esc(d.ptime)+' '+(d.pap||'AM'):'')+'</td><td>'+(d.signed?'✓ نعم Yes':'✗ لا No')+'</td><td>'+(d.contacted?'✓ نعم Yes':'✗ لا No')+'</td><td>'+(d.oriented?'✓ نعم Yes':'✗ لا No')+'</td><td>'+(d.deal?'نتعامل We deal':'لا نتعامل No deal')+'</td></tr>'});h+='</table>'}
    KINDS.forEach(function(k){var l=S.items.filter(function(i){return i.co===c.id&&i.kind===k.v});if(!l.length)return;h+='<h3>'+k.l+'</h3><table><tr><th>البند Item</th><th>التاريخ Date</th><th>الساعة Time</th><th>ملاحظة Note</th><th>تمّت Done</th></tr>';
      l.sort(function(a,b){return (a.date||'9').localeCompare(b.date||'9')||((a.ap==='PM')-(b.ap==='PM'))||(tmin(a)-tmin(b))}).forEach(function(i){h+='<tr><td>'+esc(i.title)+'</td><td dir="ltr">'+esc(i.date)+'</td><td dir="ltr">'+(i.time?esc(i.time)+' '+i.ap:'')+'</td><td>'+esc(i.note)+'</td><td>'+(i.done?'✓':'')+'</td></tr>'});h+='</table>'})});
  return h}
function plan(){var h='<h1>خطتك لشغل الأوبريشن والسكرتارية<br>Your 6-week plan</h1><h3>الروتين اليومي Daily routine</h3>';daily.forEach(function(d,i){h+='<div class="item"><b>'+(i+1)+'. '+d.name+'</b><div>'+d.detail+'</div></div>'});weeks.forEach(function(w){h+='<h3>الأسبوع '+w.n+' · Week '+w.n+': '+w.title+'</h3><p>'+w.goal+'</p><ul>'+w.items.map(function(x){return '<li>'+x+'</li>'}).join('')+'</ul>'});return h}
function practice(){var h='<h1>تمارين عملية<br>Practice exercises</h1>';topics.forEach(function(t){h+='<h3>'+t.label+': '+t.title+'</h3><p>'+t.intro+'</p><ul>'+t.items.map(function(x){return '<li>'+x+'</li>'}).join('')+'</ul>'});return h+'<p class="muted">الأسماء والأرقام وهمية. Use fake data for practice.</p>'}
function wire(){
  document.querySelectorAll('[data-tab]').forEach(function(b){b.onclick=function(){S.tab=b.dataset.tab;render()}});
  document.querySelectorAll('[data-co]').forEach(function(b){b.onclick=function(){S.active=+b.dataset.co;S.showCo=false;save('sh.active',S.active);render()}});
  document.querySelectorAll('[data-kind]').forEach(function(b){b.onclick=function(){S.kind=b.dataset.kind;S.showItem=false;render()}});
  var v=function(id){return $('#'+id).value.trim()};
  var on=function(id,f){var e=$('#'+id);if(e)e.onclick=f};
  on('newco',function(){S.showCo=true;S.editCo=false;render()});on('cancelco',function(){S.showCo=false;S.editCo=false;render()});on('editco',function(){S.editCo=true;S.showCo=false;render();window.scrollTo(0,0)});
  on('saveco',function(){if(!v('c_name'))return;if(S.editCo){var cur=S.companies.filter(function(c){return c.id===S.active})[0]||S.companies[0];cur.name=v('c_name');cur.addr=v('c_addr');cur.phone=v('c_phone');cur.mgr=v('c_mgr');cur.note=v('c_note');S.editCo=false;save('sh.companies',S.companies);render();return}var c={id:Date.now(),name:v('c_name'),addr:v('c_addr'),phone:v('c_phone'),mgr:v('c_mgr'),note:v('c_note')};S.companies.push(c);S.active=c.id;S.showCo=false;save('sh.companies',S.companies);save('sh.active',c.id);render()});
  on('delco',function(){if(!confirm('حذف الشركة وكل شغلها؟ Delete this company and all its work?'))return;var id=S.active||S.companies[0].id;S.companies=S.companies.filter(function(c){return c.id!==id});S.items=S.items.filter(function(i){return i.co!==id});S.devs=S.devs.filter(function(d){return d.co!==id});save('sh.devs',S.devs);S.active=0;save('sh.companies',S.companies);save('sh.items',S.items);render()});
  on('newitem',function(){S.showItem=true;render()});on('cancelitem',function(){S.showItem=false;S.editItem=0;render()});document.querySelectorAll('[data-edit]').forEach(function(b){b.onclick=function(){S.editItem=+b.dataset.edit;S.showItem=false;render();window.scrollTo(0,0)}});
  var EIw=S.editItem?S.items.filter(function(i){return i.id===S.editItem})[0]:null;var ap=(EIw&&EIw.ap)||'AM';document.querySelectorAll('[data-ap]').forEach(function(b){b.onclick=function(){ap=b.dataset.ap;document.querySelectorAll('[data-ap]').forEach(function(x){x.classList.toggle('on',x===b)})}});
  on('saveitem',function(){if(!v('i_title'))return;if(S.editItem){S.items.forEach(function(i){if(i.id===S.editItem){i.title=v('i_title');i.date=v('i_date');i.time=v('i_time');i.ap=ap;i.note=v('i_note')}});S.editItem=0;save('sh.items',S.items);render();return}var co=S.companies.filter(function(c){return c.id===S.active})[0]||S.companies[0];S.items.push({id:Date.now(),co:co.id,kind:S.kind,title:v('i_title'),date:v('i_date'),time:v('i_time'),ap:ap,note:v('i_note'),done:false});S.showItem=false;save('sh.items',S.items);render()});
  document.querySelectorAll('[data-done]').forEach(function(b){b.onclick=function(){S.items.forEach(function(i){if(i.id==b.dataset.done)i.done=!i.done});save('sh.items',S.items);render()}});
  document.querySelectorAll('[data-del]').forEach(function(b){b.onclick=function(){S.items=S.items.filter(function(i){return i.id!=b.dataset.del});save('sh.items',S.items);render()}});
  on('newdev',function(){S.showDev=true;render()});on('canceldev',function(){S.showDev=false;S.editDev=0;render()});document.querySelectorAll('[data-dedit]').forEach(function(b){b.onclick=function(){S.editDev=+b.dataset.dedit;S.showDev=false;render();window.scrollTo(0,0)}});
  var EDw=S.editDev?S.devs.filter(function(d){return d.id===S.editDev})[0]:null;var dd=EDw?!!EDw.deal:true;var dap=(EDw&&EDw.pap)||'AM';document.querySelectorAll('[data-dap]').forEach(function(b){b.onclick=function(){dap=b.dataset.dap;document.querySelectorAll('[data-dap]').forEach(function(x){x.classList.toggle('on',x===b)})}});document.querySelectorAll('[data-dd]').forEach(function(b){b.onclick=function(){dd=b.dataset.dd==='1';document.querySelectorAll('[data-dd]').forEach(function(x){x.classList.toggle('on',x===b)})}});
  on('savedev',function(){if(!v('d_name'))return;if(S.editDev){S.devs.forEach(function(d){if(d.id===S.editDev){d.name=v('d_name');d.contact=v('d_contact');d.note=v('d_note');d.pdate=v('d_pdate');d.ptime=v('d_ptime');d.pap=dap;d.deal=dd}});S.editDev=0;save('sh.devs',S.devs);render();return}var co=S.companies.filter(function(c){return c.id===S.active})[0]||S.companies[0];S.devs.push({id:Date.now(),co:co.id,name:v('d_name'),contact:v('d_contact'),note:v('d_note'),pdate:v('d_pdate'),ptime:v('d_ptime'),pap:dap,deal:dd,signed:false,contacted:false,oriented:false});S.showDev=false;save('sh.devs',S.devs);render()});
  document.querySelectorAll('[data-df]').forEach(function(b){b.onclick=function(){var a=b.dataset.df.split(':');S.devs.forEach(function(d){if(d.id==a[1])d[a[0]]=!d[a[0]]});save('sh.devs',S.devs);render()}});
  document.querySelectorAll('[data-dtog]').forEach(function(b){b.onclick=function(){S.devs.forEach(function(d){if(d.id==b.dataset.dtog)d.deal=!d.deal});save('sh.devs',S.devs);render()}});
  document.querySelectorAll('[data-ddel]').forEach(function(b){b.onclick=function(){if(!confirm('حذف شركة المطوّر ده؟ Delete this developer company?'))return;S.devs=S.devs.filter(function(d){return d.id!=b.dataset.ddel});save('sh.devs',S.devs);render()}});
  on('lock',showLock);on('doprint',function(){window.print()});
  if(window.__ip){var e=$('#inst');e.hidden=false;e.onclick=function(){window.__ip.prompt()}}
}
window.addEventListener('beforeinstallprompt',function(e){e.preventDefault();window.__ip=e;var b=$('#inst');if(b){b.hidden=false;b.onclick=function(){e.prompt()}}});
if('serviceWorker'in navigator)navigator.serviceWorker.register('sw.js');
showLock();
