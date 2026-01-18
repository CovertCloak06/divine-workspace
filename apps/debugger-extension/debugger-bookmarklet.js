(function(){
if(window.DD){document.getElementById('dd-overlay')?.remove();document.querySelector('style[data-dd]')?.remove();window.DD=null;return}
window.DD={logs:[],el:null};
var css=`#dd-overlay{position:fixed;bottom:10px;left:10px;width:95vw;max-width:420px;height:320px;background:#0d0d0d;border:2px solid #0ff;border-radius:8px;z-index:2147483647;font:12px monospace;color:#eee;display:flex;flex-direction:column;box-shadow:0 0 20px rgba(0,255,255,.3)}
#dd-overlay *{box-sizing:border-box;margin:0;padding:0}
.dh{display:flex;justify-content:space-between;padding:8px 10px;background:#0ff1;border-bottom:1px solid #0ff3;cursor:move}
.dh span{color:#0ff;font-weight:bold}
.db{background:transparent;border:1px solid #0ff5;color:#0ff;padding:3px 10px;cursor:pointer;border-radius:3px;font:inherit}
.db:hover{background:#0ff2}
.dt{display:flex;background:#111;border-bottom:1px solid #333}
.dt button{background:none;border:none;color:#666;padding:8px 12px;cursor:pointer;border-bottom:2px solid transparent;font:inherit}
.dt button.a{color:#0ff;border-bottom-color:#0ff}
.dc{flex:1;overflow:hidden;display:flex;flex-direction:column}
.dp{display:none;flex:1;overflow:auto;padding:10px;flex-direction:column}
.dp.a{display:flex}
.dl{padding:4px 6px;border-bottom:1px solid #222;font-size:11px}
.di{background:#1a1a1a;padding:8px 10px;margin:4px 0;border-radius:4px;border-left:3px solid #f44;font-size:11px}
.di.w{border-left-color:#fc0}
.di.g{border-left-color:#0f0}
.di b{color:#fff}
.bg{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:10px}
.out{flex:1;overflow:auto}`;
var st=document.createElement('style');st.setAttribute('data-dd','1');st.textContent=css;document.head.appendChild(st);
var ov=document.createElement('div');ov.id='dd-overlay';
ov.innerHTML=`<div class="dh" id="dh"><span>⚡ Debugger</span><div><button class="db" onclick="DD.min()">─</button><button class="db" onclick="DD.cls()">✕</button></div></div>
<div class="dt"><button class="a" data-t="con">Console</button><button data-t="ana">Analysis</button><button data-t="sec">Security</button><button data-t="el">Elements</button></div>
<div class="dc">
<div id="dp-con" class="dp a"></div>
<div id="dp-ana" class="dp"><div class="bg"><button class="db" onclick="DD.runAll()">▶ Run All</button><button class="db" onclick="DD.findDup()">Duplicates</button><button class="db" onclick="DD.findScope()">Scope</button><button class="db" onclick="DD.findSel()">Selectors</button></div><div class="out" id="ana-out"></div></div>
<div id="dp-sec" class="dp"><div class="bg"><button class="db" onclick="DD.secAll()">▶ Full Scan</button><button class="db" onclick="DD.secProto()">Protocol</button><button class="db" onclick="DD.secCook()">Cookies</button><button class="db" onclick="DD.secStore()">Storage</button><button class="db" onclick="DD.secScript()">Scripts</button><button class="db" onclick="DD.secForm()">Forms</button></div><div class="out" id="sec-out"></div></div>
<div id="dp-el" class="dp"><div class="out" id="el-list"></div></div>
</div>`;
document.body.appendChild(ov);

DD.log=function(m,t){var o=document.getElementById('dp-con'),d=document.createElement('div');d.className='dl';d.style.color=t=='e'?'#f66':t=='w'?'#fc0':'#0ff';d.textContent=m;o.appendChild(d);o.scrollTop=1e9};
DD.cls=function(){ov.remove();st.remove();window.DD=null};
DD.min=function(){ov.style.height=ov.style.height=='40px'?'320px':'40px'};

var drag=false,ox,oy;
document.getElementById('dh').onmousedown=function(e){if(e.target.tagName=='BUTTON')return;drag=true;var r=ov.getBoundingClientRect();ox=e.clientX-r.left;oy=e.clientY-r.top};
document.onmousemove=function(e){if(drag){ov.style.left=(e.clientX-ox)+'px';ov.style.top=(e.clientY-oy)+'px';ov.style.bottom='auto'}};
document.onmouseup=function(){drag=false};
document.getElementById('dh').ontouchstart=function(e){if(e.target.tagName=='BUTTON')return;drag=true;var r=ov.getBoundingClientRect(),t=e.touches[0];ox=t.clientX-r.left;oy=t.clientY-r.top};
document.ontouchmove=function(e){if(drag){var t=e.touches[0];ov.style.left=(t.clientX-ox)+'px';ov.style.top=(t.clientY-oy)+'px';ov.style.bottom='auto'}};
document.ontouchend=function(){drag=false};

ov.querySelectorAll('.dt button').forEach(function(b){b.onclick=function(){ov.querySelectorAll('.dt button').forEach(function(x){x.classList.remove('a')});ov.querySelectorAll('.dp').forEach(function(x){x.classList.remove('a')});b.classList.add('a');document.getElementById('dp-'+b.dataset.t).classList.add('a')}});

var _l=console.log,_e=console.error,_w=console.warn;
console.log=function(){_l.apply(console,arguments);DD.log(Array.from(arguments).join(' '))};
console.error=function(){_e.apply(console,arguments);DD.log(Array.from(arguments).join(' '),'e')};
console.warn=function(){_w.apply(console,arguments);DD.log(Array.from(arguments).join(' '),'w')};

DD.findDup=function(){var out=document.getElementById('ana-out'),fns={},scripts=document.querySelectorAll('script:not([src])');scripts.forEach(function(s,i){var m,r=/function\s+(\w+)\s*\(/g;while(m=r.exec(s.textContent)){if(!fns[m[1]])fns[m[1]]=[];fns[m[1]].push('script-'+(i+1))}});var dups=Object.entries(fns).filter(function(e){return e[1].length>1});out.innerHTML=dups.length==0?'<div class="di g"><b>✓ No duplicates</b></div>':dups.map(function(d){return '<div class="di w"><b>'+d[0]+'</b> in '+d[1].join(', ')+'</div>'}).join('')};
DD.findScope=function(){var out=document.getElementById('ana-out'),scripts=document.querySelectorAll('script:not([src])'),local=new Set,win=new Set;scripts.forEach(function(s){var c=s.textContent;(c.match(/window\.(\w+)/g)||[]).forEach(function(m){win.add(m.replace('window.',''))});(c.match(/(?:let|const|var)\s+(\w+)/g)||[]).forEach(function(m){local.add(m.split(/\s+/)[1])})});var issues=[];local.forEach(function(v){if(win.has(v))issues.push(v)});out.innerHTML=issues.length==0?'<div class="di g"><b>✓ No scope issues</b></div>':issues.map(function(v){return '<div class="di w"><b>'+v+'</b></div>'}).join('')};
DD.findSel=function(){var out=document.getElementById('ana-out'),scripts=document.querySelectorAll('script:not([src])'),missing=[];scripts.forEach(function(s){(s.textContent.match(/getElementById\(['"]([\w-]+)['"]\)/g)||[]).forEach(function(m){var id=m.match(/getElementById\(['"]([\w-]+)['"]\)/)[1];if(!document.getElementById(id))missing.push('#'+id)})});missing=[...new Set(missing)];out.innerHTML=missing.length==0?'<div class="di g"><b>✓ All selectors found</b></div>':missing.map(function(m){return '<div class="di"><b>'+m+'</b> not in DOM</div>'}).join('')};
DD.runAll=function(){var out=document.getElementById('ana-out');out.innerHTML='';var fns={},scripts=document.querySelectorAll('script:not([src])');scripts.forEach(function(s,i){var m,r=/function\s+(\w+)\s*\(/g;while(m=r.exec(s.textContent)){if(!fns[m[1]])fns[m[1]]=[];fns[m[1]].push(i+1)}});var dups=Object.entries(fns).filter(function(e){return e[1].length>1});var local=new Set,win=new Set;scripts.forEach(function(s){var c=s.textContent;(c.match(/window\.(\w+)/g)||[]).forEach(function(m){win.add(m.replace('window.',''))});(c.match(/(?:let|const|var)\s+(\w+)/g)||[]).forEach(function(m){local.add(m.split(/\s+/)[1])})});var scope=[];local.forEach(function(v){if(win.has(v))scope.push(v)});var missing=[];scripts.forEach(function(s){(s.textContent.match(/getElementById\(['"]([\w-]+)['"]\)/g)||[]).forEach(function(m){var id=m.match(/getElementById\(['"]([\w-]+)['"]\)/)[1];if(!document.getElementById(id))missing.push('#'+id)})});missing=[...new Set(missing)];var h='';if(dups.length)h+='<div class="di w"><b>Duplicates:</b> '+dups.map(function(d){return d[0]}).join(', ')+'</div>';if(scope.length)h+='<div class="di w"><b>Scope:</b> '+scope.join(', ')+'</div>';if(missing.length)h+='<div class="di"><b>Missing:</b> '+missing.join(', ')+'</div>';out.innerHTML=h||'<div class="di g"><b>✓ No issues!</b></div>'};

DD.secAll=function(){var out=document.getElementById('sec-out'),h='';h+='<div class="di '+(location.protocol=='https:'?'g':'')+'"><b>Protocol:</b> '+location.protocol+'</div>';h+='<div class="di"><b>Cookies:</b> '+document.cookie.split(';').filter(function(x){return x.trim()}).length+'</div>';var ls=Object.keys(localStorage);h+='<div class="di"><b>LocalStorage:</b> '+ls.length+'</div>';var ext=Array.from(document.querySelectorAll('script[src]')).filter(function(s){try{return new URL(s.src).hostname!=location.hostname}catch(e){return false}});h+='<div class="di"><b>External scripts:</b> '+ext.length+'</div>';h+='<div class="di"><b>Forms:</b> '+document.querySelectorAll('form').length+'</div>';out.innerHTML=h};
DD.secProto=function(){document.getElementById('sec-out').innerHTML='<div class="di '+(location.protocol=='https:'?'g':'')+'"><b>'+location.protocol+'</b></div>'};
DD.secCook=function(){var c=document.cookie.split(';').filter(function(x){return x.trim()});document.getElementById('sec-out').innerHTML=c.length==0?'<div class="di g"><b>No cookies</b></div>':c.map(function(x){return'<div class="di"><b>'+x.split('=')[0].trim()+'</b></div>'}).join('')};
DD.secStore=function(){var ls=Object.keys(localStorage);document.getElementById('sec-out').innerHTML=ls.length==0?'<div class="di g"><b>Empty</b></div>':ls.map(function(k){return'<div class="di"><b>'+k+'</b></div>'}).join('')};
DD.secScript=function(){var ext=Array.from(document.querySelectorAll('script[src]')).filter(function(s){try{return new URL(s.src).hostname!=location.hostname}catch(e){return false}});document.getElementById('sec-out').innerHTML=ext.length==0?'<div class="di g"><b>None</b></div>':ext.map(function(s){return'<div class="di"><b>'+new URL(s.src).hostname+'</b></div>'}).join('')};
DD.secForm=function(){var forms=document.querySelectorAll('form');document.getElementById('sec-out').innerHTML=forms.length==0?'<div class="di g"><b>No forms</b></div>':Array.from(forms).map(function(f,i){return'<div class="di"><b>Form '+(i+1)+'</b> '+(f.method||'GET')+'</div>'}).join('')};

DD.loadEl=function(){var list=document.getElementById('el-list'),els=Array.from(document.querySelectorAll('body *')).filter(function(e){return e.id!='dd-overlay'&&!e.closest('#dd-overlay')}).slice(0,100);list.innerHTML=els.map(function(e,i){return'<div class="dl" style="cursor:pointer" onclick="DD.selEl('+i+')"><span style="color:#f7a">'+e.tagName.toLowerCase()+'</span><span style="color:#7f7">'+(e.id?'#'+e.id:'')+'</span></div>'}).join('');DD.els=els};
DD.selEl=function(i){var e=DD.els[i];if(e){e.style.outline='2px solid #0ff';setTimeout(function(){e.style.outline=''},2000)}};

setTimeout(DD.loadEl,100);
DD.log('Debugger ready.');
})()
