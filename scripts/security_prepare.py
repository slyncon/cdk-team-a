"""Verify the staged Claims handler and prepare explicit, fresh scanner inputs."""

import hashlib
import json
import re
import shutil
from pathlib import Path


def prepare():
    assembly, inputs = Path('.build/cdk.out'), Path('.build/security-inputs')
    evidence = Path('.build/security/real')
    for path in (inputs, evidence):
        shutil.rmtree(path, ignore_errors=True)
        path.mkdir(parents=True)
    template = json.loads((assembly / 'ClaimsTeamStack.template.json').read_text())
    functions = [r for r in template['Resources'].values() if r['Type'] == 'AWS::Lambda::Function'
                 and r['Properties'].get('Handler') == 'index.handler'
                 and r['Properties'].get('Runtime') == 'python3.12'
                 and 'aws:asset:path' in r.get('Metadata', {})]
    if len(functions) != 1:
        raise ValueError('Expected exactly one Claims Python 3.12 handler')
    asset = (assembly / functions[0]['Metadata']['aws:asset:path']).resolve()
    if not asset.is_relative_to(assembly.resolve()) or not asset.is_dir():
        raise ValueError('Expected CDK staged directory inside the assembly')
    files = sorted(str(p.relative_to(asset)) for p in asset.rglob('*') if p.is_file())
    if (files != ['index.py']
            or (asset / 'index.py').read_bytes() != Path('handler/index.py').read_bytes()):
        raise ValueError('Unexpected Lambda inventory or handler differs from validated source')
    for folder in ('dependencies', 'iac'):
        (inputs / folder).mkdir()
    shutil.copytree(asset, inputs / 'runtime')
    shutil.copy2(assembly / 'ClaimsTeamStack.template.json', inputs / 'iac')
    shutil.copy2('requirements.lock', inputs / 'dependencies/requirements.txt')
    for name in ('package.json', 'package-lock.json'):
        shutil.copy2(name, inputs / 'dependencies')
    expected = [['requirements.txt', name, version] for name, version in re.findall(
        r'^([\w.-]+)==([^\s\\]+)', Path('requirements.lock').read_text(), re.MULTILINE)]
    npm = json.loads(Path('package-lock.json').read_text())['packages']
    expected += [['package-lock.json', p.split('node_modules/')[-1], v['version']]
                 for p, v in npm.items() if p]
    if not expected or not any(p[1] == 'boto3' for p in expected):
        raise ValueError('Missing Python SDK dependency inventory')
    coverage = {
        'expected_packages': expected, 'runtime_files': files, 'runtime_packages': 0,
        'runtime_asset': str(asset.relative_to(Path.cwd())),
        'handler_sha256': hashlib.sha256((asset / 'index.py').read_bytes()).hexdigest(),
        'packaging': 'CDK directory asset; ZIP created at publishing time, absent from assembly',
        'limitation': 'AWS-provided boto3/botocore and Python are absent from this asset',
        'platform_source': Path('requirements.txt').read_text().strip(),
    }
    (evidence / 'coverage.json').write_text(json.dumps(coverage, indent=2) + '\n')
    print(f"Prepared {len(expected)} locked packages and the verified Claims handler")


if __name__ == '__main__':
    prepare()
