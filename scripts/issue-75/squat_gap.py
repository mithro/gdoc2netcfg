"""Issue #75: after option A (bare host-record per dhcp-host name), which
single-label names in each leaf's zone would still lack a bare record, and
so stay claimable by any DHCP client sending that hostname?"""
import glob, re
for d in sorted(glob.glob('/etc/dnsmasq.d/*/generated')):
    leaf = d.split('/')[3]
    tmpl = ''.join(open(f).read() for f in glob.glob(f'/etc/dnsmasq.d/{leaf}/0*.conf'))
    m = re.search(r'^domain=([^,\s]+)', tmpl, re.M)
    if not m:
        continue
    dom = m.group(1)
    gen = ''.join(open(f).read() for f in glob.glob(f'{d}/*.conf'))
    recs = set(re.findall(r'^host-record=([^,]+),', gen, re.M))
    dhcp = set()
    for line in re.findall(r'^dhcp-host=(.*)$', gen, re.M):
        name = line.split(',')[-1]
        dhcp.add(name.split('.')[0] if name.endswith('.' + leaf) else name)
    labels = {r[:-len(dom) - 1] for r in recs if r.endswith('.' + dom)}
    single = {l for l in labels if '.' not in l}
    covered_today = {l for l in single if l in recs}
    covered_by_a = covered_today | (single & dhcp)
    gap = sorted(single - covered_by_a)
    print(f'{leaf:<6} single-label names={len(single):>3}  bare today={len(covered_today):>3}  '
          f'bare after A={len(covered_by_a):>3}  still claimable={len(gap):>3}  e.g. {gap[:6]}')
