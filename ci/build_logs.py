"""Keep detailed stage diagnostics outside bounded GitHub runner stdout."""
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def run_logged(command, directory, stage):
    if stage not in ('sdk', 'image'):
        raise ValueError('unexpected build stage')
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (stage + '.log')
    tail = deque(maxlen=120)
    private = False
    # The build receives no client profiles or credentials. Redact signing PEM
    # blocks and any runner token if a tool nevertheless writes them to stdout.
    tokens = [os.environ[k] for k in ('GITHUB_TOKEN', 'GH_TOKEN') if os.environ.get(k)]
    with path.open('w') as stream:
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, errors='replace') as process:
            for line in process.stdout:
                if re.search(r'-----BEGIN .*PRIVATE KEY-----', line):
                    private = True
                    line = '[private signing block omitted]\n'
                elif private:
                    if re.search(r'-----END .*PRIVATE KEY-----', line):
                        private = False
                    continue
                for token in tokens:
                    line = line.replace(token, '[runner token omitted]')
                stream.write(line)
                tail.append(line.rstrip('\n')[:2000])
            result = process.wait()
    metadata = {'stage': stage, 'return_code': result, 'log': path.name,
                'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                'source_commit': os.environ.get('GITHUB_SHA', 'local-unpublished')}
    (directory / (stage + '.json')).write_text(json.dumps(metadata, indent=2) + '\n')
    count = 40 if result == 0 else 120
    print(json.dumps(metadata))
    print('\n'.join(list(tail)[-count:]))
    if result:
        raise subprocess.CalledProcessError(result, command)
