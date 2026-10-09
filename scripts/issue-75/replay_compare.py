"""Issue #75: compare two replay_leaf.py results, name by name."""
import collections, json, sys
a, b = (json.load(open(f)) for f in sys.argv[1:3])
keys = sorted(set(a['answers']) | set(b['answers']))
groups = collections.defaultdict(list)
for k in keys:
    old, new = a['answers'].get(k, []), b['answers'].get(k, [])
    if old == new or sorted(old) == sorted(new):
        continue
    if sorted(set(old)) == sorted(new) and len(old) > len(new):
        groups['duplicate removed (same addresses)'].append(k)
    elif not new:
        groups['no longer answered'].append(f'{k} was {old}')
    elif not old:
        groups['newly answered'].append(f'{k} -> {new}')
    else:
        groups['ADDRESSES CHANGED'].append(f'{k}: {old} -> {new}')
for g, items in sorted(groups.items()):
    print(f'{g}: {len(items)}')
    for i in items[:8]:
        print(f'    {i}')
