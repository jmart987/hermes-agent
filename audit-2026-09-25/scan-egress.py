"""Independent static collector; never imports or runs the audited application."""
import pathlib,re,subprocess,json,urllib.request,datetime
ROOT=pathlib.Path(__file__).resolve().parent.parent
OUT=ROOT/'audit-2026-09-25'
COMMIT='28545254ddd02eaf01107a9ddf83b3ee9ae127f8'
SCOPES=('agent/','gateway/','hermes_cli/','tools/','plugins/','apps/desktop/')
def scan():
 tldfile=OUT/'iana-tlds.txt'
 if not tldfile.exists():
  tldfile.write_bytes(urllib.request.urlopen('https://data.iana.org/TLD/tlds-alpha-by-domain.txt',timeout=25).read())
 tlds={s.lower() for s in tldfile.read_text().splitlines() if s and not s.startswith('#')}
 tlds.update(('local','localhost','internal','lan','home','test','example','invalid','onion'))
 domain=r'(?<![\w/.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+(?:'+ '|'.join(sorted(map(re.escape,tlds),key=len,reverse=True))+r')(?![\w.-])'
 hosts=re.compile(domain+r'|(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])|\blocalhost\b|(?<![\w:])::1(?![\w:])',re.I)
 urls=re.compile(r'''(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*://[^\s<>"'`\\)\]}]+''')
 files=subprocess.check_output(['git','ls-tree','-r','--name-only',COMMIT],cwd=ROOT,text=True).splitlines()
 rows=[];binary=[];scanned=0
 for f in files:
  if not f.startswith(SCOPES):continue
  try:text=(ROOT/f).read_text()
  except (UnicodeError,OSError):binary.append(f);continue
  scanned+=1
  for n,line in enumerate(text.splitlines(),1):
   # JSON/JS slash escapes and regex escaped dots do not change the source line.
   line=line.replace('\\/','/').replace('\\.','.')
   spans=[]
   for m in urls.finditer(line):rows.append((f,n,'url',m.group()));spans.append(m.span())
   for m in hosts.finditer(line):
    if not any(a<=m.start()<b for a,b in spans):rows.append((f,n,'host-candidate',m.group()))
 (OUT/'egress-literals.tsv').write_text('file\tline\tkind\tliteral\n'+''.join('\t'.join(map(str,r))+'\n' for r in rows))
 (OUT/'egress-scan.json').write_text(json.dumps({'commit':COMMIT,'text_files_scanned':scanned,'binary_or_unreadable_files':binary,'occurrences':len(rows),'method':'All literal URI schemes with ://; standalone IANA/reserved-domain, IPv4-shaped, localhost and ::1 candidates; normalize escaped slash/dot; includes docs/tests; cannot prove dynamic egress','tld_source':'https://data.iana.org/TLD/tlds-alpha-by-domain.txt','observed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()},indent=2))
 return scanned,len(rows)
if __name__=='__main__':print(scan())
