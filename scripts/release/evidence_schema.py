"""Exact JSON types for release decisions. No permissive truthiness or coercion."""
import json
from security import require

def field(value, key, kind):
    require(type(value) is dict and key in value and type(value[key]) is kind,
            'SCHEMA_FIELD', 'Required field has missing or incorrect JSON type: '+key)
    return value[key]

def text(value, key):
    result=field(value,key,str)
    require(bool(result.strip()),'SCHEMA_TEXT','Required text is empty: '+key)
    return result

def strict_json(content):
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result,'JSON_DUPLICATE','Duplicate JSON field.')
            result[key]=value
        return result
    def constant(_):
        require(False,'JSON_CONSTANT','Nonstandard JSON numeric constant.')
    return json.loads(content,object_pairs_hook=pairs,parse_constant=constant)

def security_types(d, scanner=False):
    field(d,'User',str)
    for key in ['ReadonlyRootfs','Privileged']: field(d,key,bool)
    for key in ['Memory','PidsLimit','NanoCpus']: field(d,key,int)
    for key in ['CapDrop','SecurityOpt']:
        values=field(d,key,list)
        require(all(type(x) is str for x in values),'SCHEMA_SECURITY_LIST','Malformed security option list.')
    require('PortBindings' in d and (d['PortBindings'] is None or type(d['PortBindings']) is dict),
            'SCHEMA_PORTS','Port bindings must be an object or explicit null.')
    if scanner:
        field(d,'NetworkMode',str); field(d,'Networks',dict)
        for mount in field(d,'Mounts',list):
            text(mount,'Type'); text(mount,'Destination')
            if mount['Type']=='bind': text(mount,'Source'); field(mount,'RW',bool)

def scan_schema(d):
    require(field(d,'SchemaVersion',int)==2 and text(d,'ArtifactType')=='container_image','SCAN_SCHEMA','Unsupported scan schema/type.')
    metadata=field(d,'Metadata',dict); text(metadata,'ImageID')
    results=field(d,'Results',list)
    require(bool(results),'SCAN_RESULTS','Missing scan results.')
    for result in results:
        require(text(result,'Class') in ('os-pkgs','lang-pkgs'),'SCAN_CLASS','Unexpected scanner result class.')
        text(result,'Target')
        require('Error' not in result,'SCAN_ERROR','Scanner reported an error.')
        packages=field(result,'Packages',list)
        for package in packages: text(package,'Name')
        # Missing/null is not interpreted as a clean result; scanner must emit [].
        for finding in field(result,'Vulnerabilities',list):
            for key in ['Severity','PkgName','VulnerabilityID','InstalledVersion']: text(finding,key)
            require(finding['Severity'] in ('CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'),'SCAN_SEVERITY','Unsupported vulnerability severity.')
            if 'FixedVersion' in finding: field(finding,'FixedVersion',str)
