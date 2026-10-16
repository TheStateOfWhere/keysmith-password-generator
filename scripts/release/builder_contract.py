"""Strict contract for plain `docker buildx inspect default` output. No Docker calls."""
import re

def inspect_builder(raw):
    if type(raw) is not str or not raw.strip() or len(raw)>131072 or any(ord(c)<32 and c not in '\n\r\t' for c in raw):
        raise ValueError('Invalid builder output')
    header={};nodes=[];in_nodes=False;node=None
    critical={'Name','Endpoint','Status','Platforms'}
    for line in raw.splitlines():
        line=line.strip()
        if not line:continue
        if line=='Nodes:':
            if in_nodes:raise ValueError('Duplicate Nodes section')
            in_nodes=True;continue
        if ':' not in line:
            raise ValueError('Malformed builder inspection line')
        key,value=(part.strip() for part in line.split(':',1))
        if not in_nodes:
            if key in ('Name','Driver'):
                if key in header or not value:raise ValueError('Duplicate/missing builder header')
                header[key]=value
            elif key not in ('Last Activity','Error'):raise ValueError('Unexpected builder header')
            else:
                if key=='Error':raise ValueError('Builder reported an error')
        else:
            if key=='Name':
                node={};nodes.append(node)
            if key in critical:
                if node is None or key in node or not value:raise ValueError('Duplicate/missing node field')
                node[key]=value
            elif key=='Error':raise ValueError('Builder node reported an error')
            elif key in ('Driver','Last Activity','Nodes'):raise ValueError('Misplaced builder header')
            # Other BuildKit/label/GC details are informational, not identity fields.
    if header!={'Name':'default','Driver':'docker'} or len(nodes)!=1:
        raise ValueError('Expected one default Engine-integrated docker builder')
    node=nodes[0]
    if set(node)!=critical or node['Name']!='default' or node['Status']!='running':
        raise ValueError('Expected one running default builder node')
    endpoint=node['Endpoint']
    if endpoint not in ('default','unix:///var/run/docker.sock'):
        raise ValueError('Builder endpoint is not the approved local daemon')
    platforms=[p.strip().removesuffix('*') for p in node['Platforms'].split(',')]
    if not platforms or any(not re.fullmatch(r'[a-z0-9_.-]+/[a-z0-9_.-]+(?:/[a-z0-9_.-]+)?',p) for p in platforms) or not any(p in ('linux/amd64','linux/amd64/v1') for p in platforms):
        raise ValueError('Builder does not advertise the approved linux/amd64 platform')
    return endpoint
