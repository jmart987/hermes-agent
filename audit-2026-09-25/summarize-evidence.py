import pathlib,json,collections,re,urllib.parse
root=pathlib.Path(__file__).resolve().parent.parent;p=root/'audit-2026-09-25'
d=json.loads((p/'osv-results.json').read_text());details=json.loads((p/'osv-details.json').read_text())
valid=[r for r in d['results'] if r['component']['name']!='hermes-agent'];affected=[r for r in valid if r['result'].get('vulns')];ids={v['id'] for r in affected for v in r['result']['vulns']}
rows=['# Dependency findings','',f"OSV observation: {d['observed_utc']}. {len(valid)} distinct registry package/version tuples assessed. {len(affected)} match at least one advisory; {len(ids)} advisory identifiers before alias deduplication. Zero failed batches or truncated result pages.",'','The raw query includes one excluded editable project record (`hermes-agent==0.0.0`): that placeholder is not the audited Git commit/version and its matches are not dependency findings. All lockfile versions, optional dependencies and development dependencies are included. This is not an inventory of installed packages or a reachability test. No private environment or installed plugin/MCP configuration was read.','', '| Package | Lock evidence / scope | Advisory and severity | Fixed versions reported for this package |','|---|---|---|---|']
for r in affected:
 c=r['component'];evidence=[]
 for source in c['sources']:
  f,sep,loc=source.partition(':');lines=(root/f).read_text().splitlines();needle=('name = "'+c['name']+'"') if f=='uv.lock' else '"'+loc+'": {'
  n=next((i+1 for i,l in enumerate(lines) if needle in l),1)
  scope='optional/platform superset' if f=='uv.lock' else ('dev/build' if json.loads((root/f).read_text()).get('packages',{}).get(loc,{}).get('dev') else 'runtime or mixed')
  evidence.append(f'`{f}:{n}` ({scope})')
 for v in r['result']['vulns']:
  z=details[v['id']];fix=[]
  for a in z.get('affected',[]):
   if a.get('package',{}).get('name')==c['name']:
    fix += [ev['fixed'] for ran in a.get('ranges',[]) for ev in ran.get('events',[]) if 'fixed' in ev]
  sev=z.get('database_specific',{}).get('severity') or 'not supplied'
  rows.append(f"| {c['ecosystem']} `{c['name']}=={c['version']}` | {'; '.join(evidence)} | [{v['id']}](https://osv.dev/vulnerability/{v['id']}) — {sev} | {', '.join(sorted(set(fix))) or 'No fixed range supplied'} |")
(p/'DEPENDENCIES.md').write_text('\n'.join(rows)+'\n')
counts=collections.Counter();hosts=collections.defaultdict(set)
for line in (p/'egress-literals.tsv').read_text().splitlines()[1:]:
 f,n,k,u=line.split('\t');
 try:h=urllib.parse.urlsplit(u).hostname if k=='url' else u
 except ValueError:h=None
 if h:hosts[h].add(f+':'+n);counts[h]+=1
(p/'egress-hosts.tsv').write_text('host_candidate\toccurrences\tevidence\n'+''.join(h+'\t'+str(counts[h])+'\t'+';'.join(sorted(v))+'\n' for h,v in sorted(hosts.items())))
print({'packages':len(valid),'ecosystems':dict(collections.Counter(r['component']['ecosystem'] for r in valid)),'affected':len(affected),'advisory_ids':len(ids),'hosts_or_candidates':len(hosts)})
for name in ['electron','httpx2','httpcore2']:
 for r in affected:
  if r['component']['name']==name:
   print(name,'sources',r['component']['sources'])
