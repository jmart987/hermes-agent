import json,pathlib,urllib.request,concurrent.futures
p=pathlib.Path(__file__).resolve().parent;d=json.loads((p/'osv-results.json').read_text());ids=sorted({x['id'] for r in d['results'] for x in r['result'].get('vulns',[])})
def get(i):
 try:return i,json.load(urllib.request.urlopen('https://api.osv.dev/v1/vulns/'+i,timeout=30))
 except Exception as e:return i,{'error':str(e)}
with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex: records=dict(ex.map(get,ids))
(p/'osv-details.json').write_text(json.dumps(records,indent=2))
for name in ['electron','httpx2','httpcore2','serialize-javascript']:
 for r in d['results']:
  if r['component']['name']==name:
   for v in r['result'].get('vulns',[]):
    z=records[v['id']];print(name,v['id'],z.get('summary',''),z.get('database_specific',{}).get('severity',''), 'withdrawn='+str(z.get('withdrawn')))
print('records',len(records),'errors',sum('error' in x for x in records.values()))
