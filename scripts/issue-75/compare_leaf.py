"""Issue #75: classify every line a deploy of the branch's dnsmasq_leaf
output would change against the installed /etc/dnsmasq.d tree."""
import collections, pathlib, re, sys

gen = pathlib.Path(sys.argv[1]) / 'etc/dnsmasq.d'
etc = pathlib.Path('/etc/dnsmasq.d')
kinds = collections.Counter(); eg = collections.defaultdict(list)
files_new = [p.relative_to(gen) for p in gen.glob('*/generated/*.conf')]
files_old = [p.relative_to(etc) for p in etc.glob('*/generated/*.conf')
             if (gen / p.relative_to(etc).parts[0]).exists()]
for rel in sorted(set(files_new) | set(files_old)):
    new = (gen / rel).read_text().splitlines() if (gen / rel).exists() else []
    old = (etc / rel).read_text().splitlines() if (etc / rel).exists() else []
    removed = [l for l in old if l not in new]
    added = [l for l in new if l not in old]
    rm_dhcp = {re.sub(r',[^,]+$', '', l): l for l in removed if l.startswith('dhcp-host=')}
    for l in added:
        if l.startswith('dhcp-host=') and re.sub(r',[^,]+$', '', l) in rm_dhcp:
            k = 'dhcp-host renamed'
            src = rm_dhcp.pop(re.sub(r',[^,]+$', '', l)).rsplit(',', 1)[1]
            detail = f'{rel.parts[0]}: {src} -> {l.rsplit(",", 1)[1]}'
        elif l.startswith('host-record=') and '.' not in l.split('=', 1)[1].split(',')[0]:
            k, detail = 'bare host-record added', f'{rel.parts[0]}: {l}'
        else:
            k, detail = 'OTHER ADDED', f'{rel}: {l}'
        kinds[k] += 1
        if len(eg[k]) < 6: eg[k].append(detail)
    for l in list(rm_dhcp.values()) + [l for l in removed if not l.startswith('dhcp-host=')]:
        kinds['OTHER REMOVED'] += 1
        if len(eg['OTHER REMOVED']) < 6: eg['OTHER REMOVED'].append(f'{rel}: {l}')
for k, v in sorted(kinds.items()):
    print(f'{k:<24} {v:>4}')
    for e in eg[k]: print(f'      {e}')
