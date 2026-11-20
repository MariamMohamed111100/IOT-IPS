// Headless test of the live pages (devices, counters, feed, copilot), fed with real API responses (fixtures.json).
const {JSDOM}=require('jsdom'),fs=require('fs'),path=require('path'),assert=require('assert');
const html=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');
const fx=JSON.parse(fs.readFileSync(path.join(__dirname,'fixtures.json'),'utf8'));
const MOCK=['Baby Monitor','Smart TV','Ward 3','INC-1042','128 devices','96.4','37 connections','Smart Speaker','Smart Lock — Front Door'];
function boot(data){
  const dom=new JSDOM(html,{runScripts:'dangerously',pretendToBeVisual:true,url:'http://localhost:8080/',beforeParse(w){
    w.fetch=async u=>{const p=u.replace(/^https?:\/\/[^/]+/,'');let b=null;
      if(/\/api\/incidents\/[^/]+\/events/.test(p))b=data.incident_events[decodeURIComponent(p.split('/')[3])]||[];
      else if(p.startsWith('/api/zones'))b=data.zones;else if(p.startsWith('/api/devices'))b=data.devices;else if(p.startsWith('/api/events'))b=data.events;
      else if(p.startsWith('/api/incidents'))b=data.incidents;else if(p.startsWith('/api/risk'))b=data.risk;
      return {ok:true,status:200,json:async()=>b,text:async()=>JSON.stringify(b)}};
    w.WebSocket=function(){setTimeout(()=>this.onopen&&this.onopen(),0)};
    w.addEventListener('error',e=>{throw new Error('page error: '+e.message)});}});
  return dom;
}
const vis=d=>{const c=d.body.cloneNode(true);c.querySelectorAll('script,style').forEach(x=>x.remove());return c.textContent;};
const wait=ms=>new Promise(r=>setTimeout(r,ms));
let n=0;const ok=(c,m)=>{assert.ok(c,m);n++;console.log('PASS ',m)};
const txt=(d,id)=>d.getElementById(id).textContent.trim();
(async()=>{
  let dom=boot({zones:[],devices:[],events:[],incidents:[],risk:[],incident_events:{}}),w=dom.window,d=w.document;await wait(100);
  ok(!MOCK.some(m=>vis(d).includes(m)),'before login and without data no demo text is shown');
  ok(d.querySelector('#devicesTbody').textContent.includes('No devices yet'),'empty devices page explains what to do');
  ok(txt(d,'statDevices')==='0'&&txt(d,'statConf')==='—','counters start at zero, not at demo numbers');
  dom=boot(fx);w=dom.window;d=w.document;await w.eval('loadBackendState()');await wait(150);
  ok(!MOCK.some(m=>vis(d).includes(m)),'after loading real data no demo text is left on the page');
  const rows=[...d.querySelectorAll('#devicesTbody tr')];
  ok(rows.length===fx.devices.length&&rows.length>0,`devices page lists the ${fx.devices.length} real devices`);
  ok(fx.devices.every(x=>d.getElementById('devicesTbody').textContent.includes(x.name)),'every device name is shown');
  ok(txt(d,'devicesHint')===fx.devices.length+' devices','device count hint is live');
  ok(txt(d,'statDevices')===String(fx.devices.length),'counter: devices monitored');
  const hi=fx.incidents.filter(i=>i.level==='high'||i.level==='critical').length;
  ok(txt(d,'statThreats')===String(hi),'counter: active threats = high and critical incidents ('+hi+')');
  ok(/^\d+$/.test(txt(d,'statBlocked')),'counter: blocks is a number ('+txt(d,'statBlocked')+')');
  const dets=fx.events.filter(e=>/^cyber\./.test(e.type)&&!/^cyber\.(block_|ip_)/.test(e.type)&&e.data&&typeof e.data.confidence==='number');
  ok(dets.length===0||/^\d+\.\d%$/.test(txt(d,'statConf')),'counter: detection confidence is a percentage ('+txt(d,'statConf')+')');
  const top=[...fx.risk].sort((a,b)=>b.score-a.score)[0];
  ok(txt(d,'riskScore')===String(top.score)&&d.getElementById('riskFactors').children.length===(top.factors||[]).length,'risk panel shows the backend score ('+top.score+') and its '+(top.factors||[]).length+' factors');
  ok(!d.getElementById('riskNote').textContent.includes('illustrative')&&!d.getElementById('policyDecision').textContent.includes('BLOCK_SOURCE and create'),'risk panel has no demo wording');
  ok(d.getElementById('simulateEvent').closest('.panel').style.display==='none','the fake attack simulator is hidden when real data is used');
  const feed=[...d.querySelectorAll('#feedList .feed-item')];
  ok(feed.length>0&&feed.length<=12,'live feed shows the latest events ('+feed.length+')');
  ok(d.querySelectorAll('#topologySvg circle').length>=fx.devices.length+1,'overview topology draws one node per device plus the gateway');
  const ask=async q=>{d.getElementById('copilotInput').value=q;w.eval('handleSend()');await wait(1700);const b=[...d.querySelectorAll('#copilotMessages .bubble')];return b[b.length-1].textContent};
  const dev=fx.devices[0];
  let a=await ask('tell me about '+dev.device_id);ok(a.includes(dev.name)&&/trust \d+\/100/.test(a),'copilot answers about a real device: '+a.slice(0,70));
  a=await ask('Explain the latest incident');ok(a.includes(fx.incidents[0].id),'copilot explains the latest real incident');
  a=await ask('Which devices are most at risk?');ok(/Lowest trust scores/.test(a),'copilot ranks real devices by trust');
  a=await ask('Summarize the last 24 hours');ok(a.includes(fx.devices.length+' devices')&&a.includes(fx.incidents.length+' incidents'),'copilot summary uses real counts');
  a=await ask('how many blocks?');ok(/block result/.test(a),'copilot answers about blocks');
  a=await ask('<img src=x onerror="window.__p=1">');ok(!d.querySelector('#copilotMessages img')&&!w.__p,'copilot never turns input into HTML');
  console.log(`\n${n} checks passed`);process.exit(0);
})().catch(e=>{console.error('FAIL',e.message);process.exit(1)});
