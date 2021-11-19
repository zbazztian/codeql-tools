import platform
import sys
import multiprocessing
import shutil
import os
from os.path import dirname, isfile, isdir, exists
import hashlib


def system_info():
  def gb(value):
    return value / (1024**3)

  def format_gb(number):
    return '{:.2f} GB'.format(gb(number))

  if platform.system() == 'Linux':
    total_ram = format_gb(os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES'))
  else:
    total_ram = 'unknown'

  loc_ds = dirname(__file__)
  total_ds, used_ds, free_ds = [format_gb(i) for i in shutil.disk_usage(loc_ds)]
  return [
    ['platform', platform.platform()],
    ['python version', sys.version],
    ['cores', str(multiprocessing.cpu_count())],
    ['total ram', total_ram],
    ['free disk space (' + loc_ds + ')', free_ds],
    ['total disk space (' + loc_ds + ')', total_ds],
    ['used disk space (' + loc_ds + ')', used_ds],
  ]


def error(msg):
  print('ERROR: ' + str(msg), flush=True)
  sys.exit(1)


def info(msg):
  print('INFO: ' + str(msg), flush=True)


def warning(msg):
  print('WARNING: ' + str(msg), flush=True)


def clear_dir(dirpath):
  shutil.rmtree(dirpath, True)
  os.makedirs(dirpath)
  return dirpath


def make_key(s):
  sha1 = hashlib.sha1()
  sha1.update(s.encode('utf-8'))
  return sha1.hexdigest()


def read_file(fpath):
  with open(fpath, 'r') as f:
    return f.read()


def write_file(fpath, contents):
  with open(fpath, 'w') as f:
    f.write(contents)


# copy a file and make sure that the destination
# path exists (all directories)
def copy(src, dest):
  if exists(src):
    os.makedirs(dirname(dest), exist_ok=True)
    if isfile(src):
      shutil.copyfile(src, dest)
    elif isdir(src):
      shutil.copytree(src, dest)
