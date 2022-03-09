import inject
from inject import info, error, version2str, parse_version, add_versions
import sys
import subprocess
import os
from os.path import isfile, join, exists, dirname
import json
import shutil

pack_download_dir = 'codeql_inject_pack_downloads'
codeql_exec, github_token, base_name, target_name, default_suite, patterns = sys.argv[1:]
env = os.environ
env.update({'GITHUB_TOKEN': github_token})


if not isfile(codeql_exec):
  error('Cannot find executable {exec}!'.format(exec=codeql_exec))


def run_impl(args):
  print(' '.join(args), flush=True)
  try:
    output = subprocess.run(
      args,
      capture_output=True,
      check=True,
      env=env
    ).stdout.decode()
    print(output, flush=True)
    return output
  except subprocess.CalledProcessError as cpe:
    print('Command failed with exit code: ' + str(cpe.returncode))
    print('stdout:')
    print(cpe.output.decode())
    print('stderr:')
    print(cpe.stderr.decode(), flush=True)
    raise


def codeql(*args):
  args = [codeql_exec] + list(args)
  return run_impl(args)


def download_pack(pack_name):
  j = json.loads(
    codeql(
      'pack', 'download',
      '-vvv',
      '--format', 'json',
      '--force',
      '--dir', pack_download_dir,
      pack_name
    )
  )

  if len(j['packs']) > 0:
    return j['packs'][0]['packDir']


  j = json.loads(
    codeql(
      'pack', 'ls',
      '--format', 'json',
      dirname(codeql_exec)
    )
  )
  packs = j['packs']
  src = None
  for p in packs:
    if packs[p]['name'] == pack_name:
      src = dirname(p)
      break

  if src is None:
    raise Exception('Failed to download pack "' + pack_name + '".')

  ret = join(pack_download_dir, pack_name)
  shutil.copytree(src, ret)
  return ret


try:
  if exists(pack_download_dir):
    shutil.rmtree(pack_download_dir)

  existing_target_pack = download_pack(target_name)
  existing_target_hash = inject.get_pack_hash(existing_target_pack)
  _, existing_target_version = inject.get_pack_info(existing_target_pack)
  target_version = version2str(add_versions(parse_version(existing_target_version), [0, 0, 1]))
except subprocess.CalledProcessError as cpe:
  info('Unable to download existing target pack. Assuming it doesn\'t yet exist.')
  existing_target_hash = ''
  target_version = '1.0.0'

base_path = download_pack(base_name)
print('base pack downloaded to "' + base_path + '".')

# inject modifications into the base pack, to get our target pack
inject.main([
  '--pack', base_path,
  '--name', target_name,
  '--version', target_version,
  '--default-suite', default_suite,
  '--',
  patterns
])

# only publish if there is a difference between
# the existing target pack and the one we just created
target_hash = inject.get_pack_hash(base_path)
if target_hash != existing_target_hash:
  info('Hashes of existing and generated pack differ. Uploading new pack...')
  codeql(
    'pack', 'publish',
    '--threads', '0',
    '-vv',
    base_path
  )
else:
  info('Hashes of existing and generated pack are identical. Nothing to do.')
