#!/usr/bin/env bash
# Regenerate quality-on-legion-swarm.json from current rd state.
# Run after a wave completes so the manifest reflects which items are now ready.
set -euo pipefail

PARENT="${PARENT:-mallcoppro-9fd}"
OUT="${OUT:-$(dirname "$0")/quality-on-legion-swarm.json}"

python3 - "$PARENT" "$OUT" <<'PY'
import json, subprocess, re, sys

PARENT, OUT = sys.argv[1], sys.argv[2]
data = json.loads(subprocess.run(['rd','list','--all','--json'], capture_output=True, text=True).stdout)
children = [i for i in data if i.get('parent_id') == PARENT]

def parse_annotations(ctx):
    out = {}
    for line in (ctx or '').split('\n'):
        m = re.match(r'^[\s-]*(agent-type|test-depth|model-tier|artifact-type)\s*:\s*(.+?)\s*$', line, re.I)
        if m:
            key = m.group(1).lower().replace('-', '_')
            if key not in out:
                out[key] = m.group(2).strip()
    return out

manifest = {
    "parent": PARENT,
    "design_doc": "docs/design/quality-on-legion.md",
    "design_campfire": "74560d7d779998a781657b37a053e2501e07a382933e4ebe909883bc01f9fd50",
    "items": [],
}

for c in children:
    if c.get('status') in ('cancelled', 'failed'):
        continue
    ann = parse_annotations(c.get('context',''))
    manifest['items'].append({
        "id": c['id'],
        "title": c['title'],
        "type": c['type'],
        "status": c['status'],
        "blocked_by": c.get('blocked_by') or [],
        "agent_type": ann.get('agent_type', 'implementer'),
        "test_depth": ann.get('test_depth', ''),
        "model_tier": ann.get('model_tier', 'sonnet'),
        "artifact_type": ann.get('artifact_type', 'code'),
    })

manifest['items'].sort(key=lambda i: (i['type'], i['id']))
manifest['summary'] = {
    "total": len(manifest['items']),
    "by_agent_type": {},
    "by_status": {},
    "ready_now": [i['id'] for i in manifest['items']
                  if i['status'] == 'inbox' and not i['blocked_by']],
}
for i in manifest['items']:
    manifest['summary']['by_agent_type'][i['agent_type']] = \
        manifest['summary']['by_agent_type'].get(i['agent_type'], 0) + 1
    manifest['summary']['by_status'][i['status']] = \
        manifest['summary']['by_status'].get(i['status'], 0) + 1

with open(OUT, 'w') as f:
    json.dump(manifest, f, indent=2)

print(f"wrote {OUT}")
print(f"  total: {manifest['summary']['total']}")
print(f"  ready: {len(manifest['summary']['ready_now'])}")
print(f"  by_status: {manifest['summary']['by_status']}")
PY
