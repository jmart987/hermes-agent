import pathlib,re,subprocess,json,hashlib
root=pathlib.Path(__file__).resolve().parent.parent;p=root/'audit-2026-09-25';base='28545254ddd02eaf01107a9ddf83b3ee9ae127f8'
text=(p/'AUDIT.md').read_text();bad=[];checked=set();source_cache={}
for f,n in re.findall(r'(?<![\w/])((?:agent|gateway|hermes_cli|tools|apps)/[\w./-]+\.(?:py|tsx?|cjs)|(?:batch_runner\.py|pyproject\.toml|uv\.lock)):(\d+)',text):
 if (f,n) in checked:continue
 checked.add((f,n))
 if f not in source_cache:source_cache[f]=subprocess.check_output(['git','show',base+':'+f],cwd=root).decode()
 raw=source_cache[f]
 if not 1<=int(n)<=len(raw.splitlines()):bad.append((f,n))
assert not bad,bad
assert text.rstrip().splitlines()[-1]=='HERMESAUDIT-DONE'
assert '/Users/' not in text and '/private/tmp/' not in text
for i in range(1,9):assert re.search(r'^## '+str(i)+r'\.',text,re.M)
assert subprocess.run(['git','diff','--quiet',base,'--','agent','gateway','hermes_cli','tools','plugins','apps/desktop','uv.lock','package-lock.json'],cwd=root).returncode==0
raw=json.loads((p/'osv-results.json').read_text());assert raw['queried']==raw['total'] and raw['total'] in (2800,2801) and not raw['errors']
assert all(not r['result'].get('next_page_token') for r in raw['results'])
valid=[r for r in raw['results'] if r['component']['name']!='hermes-agent'];assert len(valid)==2800
assert sum(bool(r['result'].get('vulns')) for r in valid)==21
for f in p.glob('*.py'):compile(f.read_text(),str(f),'exec')
summary=text.split('## Scope')[0];lines=[l for l in summary.splitlines() if l and not l.startswith('#')];assert len(lines)<=12,len(lines)
result={'audited_source':base,'source_unchanged':True,'citation_locations_validated':len(checked),'summary_lines':len(lines),'osv_registry_components':len(valid),'affected_package_versions':21,'failed_batches':0,'unread_result_pages':0,'third_party_code_executed':False}
(p/'verification.json').write_text(json.dumps(result,indent=2)+'\n');print(result)
