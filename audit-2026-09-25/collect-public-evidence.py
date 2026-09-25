import pathlib,re,subprocess,json,urllib.request,datetime,collections
root=pathlib.Path(__file__).resolve().parent.parent; out=root/'audit-2026-09-25'
files=subprocess.check_output(['git','ls-files'],cwd=root,text=True).splitlines()
scopes=('agent/','gateway/','hermes_cli/','tools/','plugins/','apps/desktop/')
url=re.compile(r'''(?:https?|wss?|ftp|ssh)://[^\s<>"'`\\)\]}]+''')
host=re.compile(r'''(?<![\w/.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+(?:com|org|net|dev|io|ai|app|co|cloud|sh|cn|us|gov|edu|local|internal|run|tech|xyz|me|fr|de|uk|jp|so|gg)(?![\w.-])|(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])|\blocalhost\b''')
rows=[]; scanned=0; binary=[]
for f in files:
 if not f.startswith(scopes):continue
 try:t=(root/f).read_text()
 except (UnicodeError,OSError):binary.append(f);continue
 scanned+=1
 for n,line in enumerate(t.splitlines(),1):
  spans=[]
  for m in url.finditer(line):
   rows.append((f,n,'url',m.group()));spans.append(m.span())
  for m in host.finditer(line):
   if not any(a<=m.start()<b for a,b in spans):rows.append((f,n,'host-candidate',m.group()))
(out/'egress-literals.tsv').write_text('file\tline\tkind\tliteral\n'+''.join('\t'.join(map(str,r))+'\n' for r in rows))
(out/'egress-scan.json').write_text(json.dumps({'commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'text_files_scanned':scanned,'binary_or_unreadable_files':binary,'occurrences':len(rows),'method':'lexical URLs plus standalone domain/IP candidates; includes tests/docs/examples; dynamic URLs require call-site review'},indent=2))
queries={}
def add(eco,name,version,source):
 if name and version:queries.setdefault((eco,name,version),[]).append(source)
uv=(root/'uv.lock').read_text()
for block in uv.split('[[package]]')[1:]:
 name=re.search(r'^name = "([^"]+)"',block,re.M);ver=re.search(r'^version = "([^"]+)"',block,re.M)
 if name and ver and re.search(r'^source = \{ registry = ',block,re.M):add('PyPI',name[1],ver[1],'uv.lock')
for f in files:
 if f.endswith('package-lock.json'):
  lock=json.loads((root/f).read_text())
  for p,data in lock.get('packages',{}).items():
   if p and data.get('version') and not data.get('link'):add('npm',data.get('name') or p.split('node_modules/')[-1],data['version'],f+':'+p)
components=[{'ecosystem':e,'name':n,'version':v,'sources':s} for (e,n,v),s in sorted(queries.items())]
(out/'dependency-components.json').write_text(json.dumps(components,indent=2))
def req(url,payload=None):
 data=json.dumps(payload).encode() if payload is not None else None
 return json.load(urllib.request.urlopen(urllib.request.Request(url,data=data,headers={'Content-Type':'application/json','User-Agent':'public-source-static-audit'}),timeout=45))
for cve in ['CVE-2026-9350','CVE-2026-9367','CVE-2026-85106','CVE-2026-85107']:
 try:(out/(cve+'.json')).write_text(json.dumps(req('https://cveawg.mitre.org/api/cve/'+cve),indent=2))
 except Exception as e:(out/(cve+'.error')).write_text(str(e))
results=[];errors=[]
for i in range(0,len(components),100):
 batch=components[i:i+100]
 try:
  response=req('https://api.osv.dev/v1/querybatch',{'queries':[{'package':{'ecosystem':c['ecosystem'],'name':c['name']},'version':c['version']} for c in batch]})
  for c,res in zip(batch,response['results']):results.append({'component':c,'result':res})
 except Exception as e:errors.append({'start':i,'count':len(batch),'error':str(e)})
 (out/'osv-results.json').write_text(json.dumps({'observed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'queried':len(results),'total':len(components),'errors':errors,'results':results},indent=2))
print(json.dumps({'scanned_files':scanned,'literals':len(rows),'components':dict(collections.Counter(c['ecosystem'] for c in components)),'queried':len(results),'errors':errors,'affected_components':sum(bool(r['result'].get('vulns')) for r in results)}))
