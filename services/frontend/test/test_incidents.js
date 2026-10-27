// Headless test of the dashboard's incident views, fed with REAL API responses (fixtures.json, captured from the running backend).
const {JSDOM}=require('jsdom'),fs=require('fs'),path=require('path'),assert=require('assert');
const html=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');
const fx=JSON.parse(fs.readFileSync(path.join(__dirname,'fixtures.json'),'utf8'));
const EVIL='<img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script>';
function boot(mutate){
  const data=JSON.parse(JSON.stringify(fx)); if(mutate)mutate(data);
  const dom=new JSDOM(html,{runScripts:'dangerously',pretendToBeVisual:true,url:'http://localhost:8080/',beforeParse(w){
    w.fetch=async u=>{const p=u.replace(/^https?:\/\/[^/]+/,'');let body=null;
      if(/\/api\/incidents\/[^/]+\/events/.test(p))body=data.incident_events[decodeURIComponent(p.split('/')[3])]||[];
      else if(p.startsWith('/api/zones'))body=data.zones;else if(p.startsWith('/api/devices'))body=data.devices;
      else if(p.startsWith('/api/events'))body=data.events;else if(p.startsWith('/api/incidents'))body=data.incidents;else if(p.startsWith('/api/risk'))body=data.risk;
      return {ok:true,status:200,json:async()=>body,text:async()=>JSON.stringify(body)}};
    w.WebSocket=function(){setTimeout(()=>this.onopen&&this.onopen(),0)};
    w.addEventListener('error',e=>{throw new Error('page error: '+e.message)});}});
  return dom;
}
const wait=ms=>new Promise(r=>setTimeout(r,ms));
let passed=0;const ok=(c,m)=>{assert.ok(c,m);passed++;console.log('PASS ',m)};
(async()=>{
  let dom=boot(),w=dom.window,d=w.document;
  await w.eval('loadBackendState()');await wait(100);
  const cards=[...d.querySelectorAll('#incidentList .incident-card')];
  ok(cards.length===fx.incidents.length&&cards.length>0,`incident list shows the ${fx.incidents.length} real incidents`);
  ok(!d.getElementById('incidentList').textContent.includes('INC-1042')&&!d.getElementById('view-incident-detail').textContent.includes('DDoS Traffic Surge'),'no mock incidents are left in the incident views');
  const crit=cards.find(c=>c.classList.contains('critical'));ok(!!crit,'critical/high incidents get the red style');
  const target=fx.incidents.find(i=>i.level==='critical');
  d.querySelector(`[data-incident="${target.id}"]`).click();await wait(150);
  ok(d.getElementById('view-incident-detail').classList.contains('active'),'clicking an incident opens its detail view');
  ok(d.getElementById('incTitle').textContent.includes('Critical'),'title shows the incident summary');
  const a=d.querySelector('#incMitre a');ok(a&&/^https:\/\/attack\.mitre\.org\/techniques\/T\d{4}\/$/.test(a.href)&&a.rel.includes('noopener'),'MITRE technique is a safe link: '+(a&&a.textContent.trim()));
  ok(d.getElementById('incFactors').textContent.includes('no factor breakdown'),'the factor panel explains that this source sends none');
  ok(d.querySelectorAll('#incTabs button').length===2,'two report tabs (technical, plain language)');
  ok(d.querySelector('#incReport table')&&d.getElementById('incReport').textContent.includes('MITRE'),'technical report renders with tables');
  d.querySelector('#incTabs button[data-tab="plain"]').click();
  ok(d.getElementById('incReport').textContent.includes('What happened?'),'plain-language tab switches');
  ok(d.getElementById('incCopy').hidden,'no copy button when the source sends no notification text');
  ok(d.getElementById('incScore').textContent.includes('IPS '),'header shows the IPS score next to the incident score');
  ok(d.querySelectorAll('#incTimeline .timeline-item').length===fx.incident_events[target.id].length,'timeline lists every event');
  ok(d.querySelectorAll('#incActions li').length>=1,'response actions are listed');
  // device panel
  w.eval("openEntity({kind:'device',id:'cam_001'})");
  ok(d.body.textContent.includes('IPS alerts'),'device panel shows IPS alerts');
  // XSS: hostile text inside the report and event fields must stay text
  dom=boot(data=>{const evs=data.incident_events[target.id];evs.forEach(e=>{if(e.data&&e.data.details){e.data.details.reports.technical='# '+EVIL+'\n| a | '+EVIL+' |\n- '+EVIL;e.data.details.reports.executive=EVIL;e.data.details.mitre_technique='T1110" onmouseover="window.__pwned=3'}e.data.src_ip=EVIL});});
  w=dom.window;d=w.document;await w.eval('loadBackendState()');await wait(100);
  d.querySelector(`[data-incident="${target.id}"]`).click();await wait(150);
  ok(!d.querySelector('#view-incident-detail img, #view-incident-detail script'),'hostile HTML in reports and events is not turned into elements');
  ok(d.getElementById('incReport').textContent.includes('<img'),'hostile text is shown as plain text');
  ok(!d.querySelector('#incMitre a'),'a malformed MITRE id is not turned into a link');
  ok(!w.__pwned,'no injected script ran');
  // update: the same incident id re-sent with more events refreshes the open view
  dom=boot();w=dom.window;d=w.document;await w.eval('loadBackendState()');await wait(100);
  d.querySelector(`[data-incident="${target.id}"]`).click();await wait(100);
  ok(d.querySelectorAll('#incidentList .incident-card').length===fx.incidents.length,'incident list is not duplicated after refresh');
  console.log(`\n${passed} checks passed`);process.exit(0);
})().catch(e=>{console.error('FAIL',e.message);process.exit(1)});
