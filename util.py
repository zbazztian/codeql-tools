import platform
import sys
import multiprocessing
import shutil
import os
from os.path import dirname

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
