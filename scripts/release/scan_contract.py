"""Two independent offline scanner outputs must agree; never infer a clean array.

Trivy's typed template pass emits explicit arrays. Native JSON supplies its actual
image identity and corroborating inventory/findings. No decision uses an omitted
native vulnerability field as a zero count. Malformed present fields always fail.
"""
import json
from pathlib import Path
import sys
from evidence_schema import field, text, scan_schema
from security import require, SecurityError
from checks import load

def combine(native_path, explicit_path, destination):
    native=load(native_path); explicit=load(explicit_path)
    require(type(explicit) is list,'CONTRACT_RESULTS','Typed scanner results must be an array.')
    require(field(native,'SchemaVersion',int)==2 and text(native,'ArtifactType')=='container_image','CONTRACT_METADATA','Invalid native scan identity schema.')
    text(field(native,'Metadata',dict),'ImageID')
    original=field(native,'Results',list)
    canonical=dict(native,Results=explicit)
    scan_schema(canonical)
    require(len(original)==len(explicit),'CONTRACT_COUNT','Scanner result counts differ.')
    for raw,typed in zip(original,explicit):
        require(type(raw) is dict,'CONTRACT_RESULT','Malformed native result.')
        require('Error' not in raw,'CONTRACT_ERROR','Native scanner reported an error.')
        if 'Vulnerabilities' in raw:
            field(raw,'Vulnerabilities',list)
            require(raw['Vulnerabilities']==typed['Vulnerabilities'],'CONTRACT_FINDINGS','Independent scanner findings differ.')
        else:
            require(typed['Vulnerabilities']==[],'CONTRACT_FINDINGS','Native scanner omitted nonempty findings.')
        # The native inventory must itself be explicit; omit nothing else silently.
        field(raw,'Packages',list)
        left={k:v for k,v in raw.items() if k!='Vulnerabilities'}
        right={k:v for k,v in typed.items() if k!='Vulnerabilities'}
        require(left==right,'CONTRACT_INVENTORY','Independent scan target/class/package inventories differ.')
    with Path(destination).open('x',encoding='utf-8') as stream:
        json.dump(canonical,stream,indent=2);stream.write('\n')

if __name__=='__main__':
    try: combine(*sys.argv[1:])
    except Exception as error:
        code=error.code if isinstance(error,SecurityError) else 'CONTRACT_IO_OR_SCHEMA'
        print('Scanner contract failed ['+code+']; no clean scan claimed.',file=sys.stderr);sys.exit(2)
