import platform
import argparse
import sys
import glob
import os
from os.path import isfile, isdir, dirname, join, relpath, basename
import subprocess
import csv
import shutil
import re
import hashlib
from distutils.dir_util import copy_tree
from datetime import datetime
import inject
import json
import util
from util import error, warning, info


def change_ext(extfrom, extto, path):
  return re.sub(re.escape(extfrom) + '$', extto, path)


def remove(fpath):
  if isfile(fpath):
    os.remove(fpath)


def is_db(dbpath):
  return isfile(join(dbpath, 'codeql-database.yml'))


def get_db_lang(dbpath):
  DB_LANG_PATTERN = re.compile('^(primaryLanguage:\s+")(\S+)"(.*)$', re.MULTILINE)
  dbyml = join(dbpath, 'codeql-database.yml')
  contents = util.read_file(dbyml)
  match = DB_LANG_PATTERN.search(contents)
  lang = None
  if not match:
    for f in os.listdir(dbpath):
      if isdir(join(dbpath, f)) and f[0:3] == 'db-':
        if not lang is None:
          raise Exception('Database "' + dbpath + '" appears to have multiple languages. Unable to determine primary one!')
        return f[3:]
    raise Exception('Unable to determine language of database "' + dbpath + '"!')
  else:
    return match.group(2)


def init_codeql(codeql_path):

  def codeql(*args):
    args = [codeql_path] + list(args)
    print(' '.join(args), flush=True)
    try:
      output = subprocess.run(
        args,
        capture_output=True,
        check=True
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

  return codeql


def codeql_bind_search_path(codeql, search_path):
  def codeql_bound(*args):
    args = list(args)
    if len(args) >= 2 and (
      (
        args[0] == 'database' and args[1] in ['create', 'analyze', 'run-queries', 'interpret-results']
      ) or (
        args[0] == 'resolve' and args[1] in ['queries', 'qlpacks']
      ) or (
        args[0] == 'pack' and args[1] in ['publish']
      ) or (
        args[0] == 'query' and args[1] in ['run', 'compile']
      )
    ):
      args = args[0:2] + ['--search-path', search_path] + args[2:]

    return codeql(*args)

  return codeql_bound



def read_bqrs(codeql, bqrs_path, resultset='#select', entities='url'):
  output = re.split(
    '\r?\n', codeql(
      'bqrs', 'decode',
      '--format', 'csv',
      '--no-titles',
      '--result-set', resultset,
      '--entities', entities,
      bqrs_path
    )
  )

  for row in csv.reader(o for o in output if o):
    yield row


def get_pack_from_file(path):
  if inject.is_pack(path):
    return path
  parent = dirname(path)
  if parent == path:
    return None
  return get_pack_from_file(parent)


def pack_relpath(path):
  return relpath(path, get_pack_from_file(path))


def get_bqrs(query_path, dbpath):
  return join(
    dbpath,
    'results',
    inject.get_pack_info(get_pack_from_file(query_path))[0],
    re.sub('\.ql$', '.bqrs', pack_relpath(query_path))
  )


def get_query_results(codeql, qls, dbpath):
  for q in resolve_queries(codeql, qls):
    yield get_bqrs(q, dbpath)


def resolve_queries(codeql, qls):
  queries = re.split('\r?\n', codeql(
    'resolve', 'queries',
    qls
  ))
  for q in queries:
    if q:
      yield q


def query_metadata(qlfile):
  PATTERN_METADATA = re.compile('^\s*/\*\*(.*?)\*/.*$', flags=re.DOTALL)
  PATTERN_LEADING_STAR = re.compile('^\s*\*?\s*', flags=re.MULTILINE)
  PATTERN_METADATA_LINE = re.compile('^@(\S+)\s+(.*?)(?=(@|\Z))', flags=re.MULTILINE|re.DOTALL)

  result = {}

  # extract metadata section
  qlcontents = util.read_file(qlfile)
  m = PATTERN_METADATA.match(qlcontents)
  if not m:
    return result
  metadata_section = m.group(1)

  # remove leading ' * ' from metadata section
  metadata_section = PATTERN_LEADING_STAR.sub('', metadata_section)

  # extract metadata lines
  for ml in PATTERN_METADATA_LINE.findall(metadata_section):
    result[ml[0]] = ml[1].rstrip()

  return result


def html_tag(tag, value, attributes = {}):
  if not isinstance(value, str):
    value = ''.join(value)
  attrstr = ' '.join('{key}="{value}"'.format(key=a, value=attributes[a]) for a in attributes)
  return '<{tag} {attrstr}>{value}</{tag}>'.format(
    attrstr=attrstr,
    tag=tag,
    value=value
  )


def table(contents):
  return html_tag('table', contents, {'border': '1'})


def tr(contents):
  return html_tag('tr', contents)


def th(contents):
  return html_tag('th', contents, {'align': 'center'})


def td(contents):
  return html_tag('td', contents, {'align': 'center'})


def h1(contents):
  return html_tag('h1', contents)


def html_table(headers, rows):
  return table(
    [tr(th(h) for h in headers)] + [
      tr(
        td(c) for c in r
      ) for r in rows
    ]
  )


def get_loc(codeql, debug_pack, dbpath):
  result = []
  for ql in resolve_queries(codeql, join(debug_pack, 'loc_queries.qls')):
    bqrs = get_bqrs(ql, dbpath)
    for r in read_bqrs(codeql, bqrs, '#select'):
      result.append([query_metadata(ql)['id']] + r)
  return result


def get_query_source_sink_counts(codeql, debug_pack, dbpath):
  result = []
  for ql in resolve_queries(codeql, join(debug_pack, 'source_sink_queries.qls')):
    bqrsf = get_bqrs(ql, dbpath)
    metadata = query_metadata(ql)
    for r in read_bqrs(codeql, bqrsf, 'source_and_sink_counts'):
      result.append([metadata['id'] + ': ' + r[0], r[1], r[2]])

  return result


def get_external_api_with_untrusted_data_counts(codeql, debug_pack, dbpath):
  result = []
  for ql in resolve_queries(codeql, join(debug_pack, 'untrusted_data_count_query.qls')):
    bqrs = get_bqrs(ql, dbpath)
    for r in read_bqrs(codeql, bqrs, '#select', 'string'):
      result.append(r)
  return result


def get_dependencies(codeql, pack, dbpath):
  ql = join(pack, 'dependencies.ql')
  bqrs = get_bqrs(ql, dbpath)
  return read_bqrs(codeql, bqrs, '#select')


def codeql_executable_name():
  if platform.system() == 'Windows':
    return 'codeql.exe'
  else:
    return 'codeql'


def is_codeql_distro(directory):
  return isdir(join(directory, 'tools')) and \
         isfile(join(directory, codeql_executable_name()))


def find_codeql_distros(directory):
  for exec_candidate in glob.iglob(
    join(directory, '**', codeql_executable_name()),
    recursive=True
  ):
    candidate_distro = dirname(exec_candidate)
    if is_codeql_distro(candidate_distro):
      yield candidate_distro


def ls_dbs(directory):
  if isdir(directory):
    if is_db(directory):
      yield directory
    else:
      for f in os.listdir(directory):
        candidate = join(directory, f)
        if is_db(candidate):
          yield candidate


def basedir():
  return dirname(__file__)


def supported_languages():
  return [
    'javascript',
    'java',
    'go',
    'csharp',
    'python'
  ]


def debug(args):
  info('basedir: ' + basedir())

  if isdir(args.codeql_path):
    info('Attempting to find a codeql distribution under given directory "' + args.codeql_path + '"...')
    distros = list(find_codeql_distros(args.codeql_path))
    if not distros:
      error('Could not find any codeql distributions under "' + args.codeql_path + '"!')
    elif len(distros) > 1:
      warning('Found multiple distributions. Selecting first one of:' + os.linesep + os.linesep.join(distros))
    args.codeql_path = join(distros[0], codeql_executable_name())
  if not isfile(args.codeql_path):
    error('Given path is not a CodeQL executable: ' + args.codeql_path)
  info('codeql executable to be used: ' + args.codeql_path)
  codeql = init_codeql(args.codeql_path)

  dbs = [db for db in ls_dbs(args.db_path) if get_db_lang(db) in supported_languages()]
  if not dbs:
    error('No databases with supported languages found under "' + args.db_path + '"!')
  info('Databases to be debugged:' + os.linesep + os.linesep.join(dbs))

  if args.search_path is None:
    args.search_path = join(dirname(args.codeql_path), 'qlpacks')
  info('search path: ' + args.search_path)

  info('output directory: ' + args.output_dir)
  util.clear_dir(args.output_dir)

  info('testing codeql executable...')
  codeql('version')
  codeql('resolve', 'qlpacks')

  for db in dbs:
    report(
      db,
      codeql,
      args.output_dir,
      args.search_path,
      args.ram,
      args.threads,
      args.repo_url
    )


def report(db_path, codeql, output_dir, search_path, ram, threads, repo_url):
  dbname = basename(db_path.rstrip(os.sep))
  db_output_dir = join(output_dir, dbname)

  lang = get_db_lang(db_path)
  info('language: ' + lang)

  tmpdir = join(output_dir, 'tmp')
  info('temp directory: ' + tmpdir)
  util.clear_dir(tmpdir)

  debug_pack = join(basedir(), 'debug', lang + '-debug-pack')
  info('debug pack at: ' + debug_pack)

  pack = inject.find_standard_query_pack(search_path, lang)
  info('standard (unmodified) query pack found at: ' + pack)

  modified_query_pack = join(tmpdir, 'modified-pack')
  info('modified query pack to be created at: ' + modified_query_pack)
  util.copy(pack, modified_query_pack)

  search_path = join(basedir(), 'debug') + os.pathsep + tmpdir + os.pathsep + search_path
  info('search path to be used for codeql: ' + search_path)
  codeql = codeql_bind_search_path(codeql, search_path)

  inject_string = ''
  for q in resolve_queries(codeql, join(debug_pack, 'source_sink_queries.qls')):
    if inject_string:
      inject_string = inject_string + '\n'
    inject_string = inject_string + join(debug_pack, 'SourcesAndSinks.qll') + os.pathsep + pack_relpath(q)

  inject.main([
    '--pack', modified_query_pack,
    inject_string
  ])

  analysis_params = [
    'database', 'run-queries',
  ] + (['--ram', ram] if ram != '0' else []) + [
    '--threads', threads,
    db_path,
    join(debug_pack, 'default.qls')
  ]
  codeql(*analysis_params)

  query_source_sink_counts = sorted(
    get_query_source_sink_counts(codeql, debug_pack, db_path),
    key=lambda el: el[0]
  )

  externalAPIWithUntrustedDataCounts = get_external_api_with_untrusted_data_counts(codeql, debug_pack, db_path)

  dependencies = get_dependencies(codeql, debug_pack, db_path)

  loc = get_loc(codeql, debug_pack, db_path)

  with open(join(output_dir, dbname + '.html'), 'w') as f:
    f.write('<html>\n<body>\n')

    # system information
    f.write(h1('System information'))
    f.write(
      html_table(
        ['component', 'information'],
        util.system_info()
      )
    )

    f.write(h1('Repository information'))
    f.write(
      html_table(
        ['key', 'value'],
        [['url', repo_url if repo_url else 'unspecified']]
      )
    )

    f.write(h1('Misc'))
    f.write(
      html_table(
        ['key', 'value'],
        [['language', lang]] + loc
      )
    )

    f.write(h1('Dependencies'))
    f.write(
      html_table(
        ['name', 'uses'],
        dependencies
      )
    )

    # sources and sinks
    f.write(h1('Summary of Sources and Sinks'))
    f.write(
      html_table(
        ['query id: configuration', '#sources', '#sinks'],
        query_source_sink_counts
      )
    )

    # external apis with untrusted data counts
    f.write(h1('External APIs with untrusted data'))
    f.write(
      html_table(
        ['API', '#uses', '#untrusted sources'],
        externalAPIWithUntrustedDataCounts
      )
    )

    f.write('</body></html>\n')


  # clean tmp directory
  shutil.rmtree(tmpdir, True)


#
#      f.write('<tr>\n')
#      f.write('  <td><a href="{relpath}">{nodetype}</a></td>\n'.format(
#        relpath=relpath(detail_file, outdir),
#        nodetype=n
#      ))
#      f.write('  <td>{count}</td>\n'.format(count=str(node_counts[n])))
#      f.write('</tr>\n')
#
#      with open(detail_file, 'w') as df:
#        df.write('<html>\n<body>\n')
#        df.write('<h2>{nodetype} (code-only results)</h2>\n'.format(nodetype=n))
#        for r in nodes.get(n, []):
#          df.write(
#            '<a href="{serverurl}/{repo_id}/blob/{sha}{fname}/#L{startline}-L{endline}">{fname}:{startline}</a><br>\n'.format(
#              serverurl=server_url,
#              repo_id=repo_id,
#              sha=sha,
#              fname=r[0],
#              startline=r[1],
#              endline=r[2]
#            )
#          )
#        df.write('</body>\n</html>\n')
#
#    f.write('</table>\n')
#
#    # dependencies
#    f.write('<h1>Dependencies</h1>\n')
#    f.write('<table>\n')
#    f.write('<tr>\n')
#    f.write('  <th align="left">Name</th>\n')
#    f.write('  <th align="left">#References</th>\n')
#    f.write('</tr>\n')
#
#    for d in dependencies:
#      f.write('<tr>\n')
#      f.write('  <td>{name}</td>\n'.format(name=d[0]))
#      f.write('  <td>{count}</td>\n'.format(count=d[1]))
#      f.write('</tr>\n')
#
#    f.write('</table>\n')
#
#    # analysis runs
#    f.write('<h1>Analyses</h1>\n')
#    f.write('<ul>\n')
#    for fname, date, qdurations in runs:
#      duration_file = join(detail_dir, make_key(fname + str(date)) + '.html')
#
#      f.write(
#        '<li><b><a href="{duration_file}">{date}</a></b> (<a href="{log_file}">{logname}</a>)</li>\n'.format(
#          duration_file=relpath(duration_file, outdir),
#          date=str(date),
#          log_file=relpath(fname, outdir),
#          logname=relpath(fname, logdir)
#        )
#      )
#
#      with open(duration_file, 'w') as df:
#        df.write('<html>\n<body><ol>\n')
#        for query, duration, pattern, idx in qdurations:
#          df.write('<li>{query} (<b>duration: {duration}</b>) (<b>index: {index}</b>)</li>\n'.format(
#            query=query,
#            duration=pattern,
#            index=idx
#          ))
#        df.write('</ol></body>\n</html>\n')
#
#    f.write('</ul>\n')
#
#    # log files
#    f.write('<h1>Log Files</h1>\n')
#    f.write('<table>\n')
#    f.write('<tr>\n')
#    f.write('  <th align="left">File</th>\n')
#    f.write('</tr>\n')
#    for logf in sorted(glob.glob(join(logdir, '**'), recursive=True)):
#      if isfile(logf):
#        rel_logf = relpath(logf, outdir)
#        name = relpath(logf, logdir)
#
#        f.write('<tr>\n')
#        f.write('  <td><a href="{relpath}">{name}</a></td>\n'.format(
#          relpath=rel_logf,
#          name=name
#        ))
#        f.write('</tr>\n')
#
#    f.write('</table>\n')
#    f.write('</body>\n</html>\n')

'''

  # copy log files from database
  original_logdir = join(dbpath, "log")
  logdir = join(detail_dir, "log")
  if isdir(original_logdir):
    copy_tree(original_logdir, logdir)

  # remove .log extensions from the copied files
  for logf in glob.glob(join(logdir, '**', '*.log'), recursive=True):
    if isfile(logf):
      os.rename(logf, change_ext('.log', '', logf))

  debug_pack = lang + '-debug-pack'
  debug_pack_path = join(here, debug_pack)


  def get_dependencies():
    result = []
    qlf = join(debug_pack_path, 'dependencies.ql')

    codeql(
      'database', 'run-queries',
      '--search-path', ql_searchpath,
      '--threads', '0',
      '--rerun',
      dbpath,
      qlf
    )

    relqlf = relpath(qlf, here)
    bqrsf = join(
      dbpath,
      'results',
      change_ext('.ql', '.bqrs', relqlf)
    )
    csvf = change_ext('.bqrs', '.csv', bqrsf)
    codeql(
      'bqrs', 'decode',
      '--no-titles',
      '--format', 'csv',
      '--output', csvf,
      bqrsf
    )

    with open(csvf, 'r') as f:
      for row in csv.reader(f):
        depname = row[0]
        count = row[1]
        result.append((depname, count))

    remove(csvf)

    return result


  def get_source_and_sink_counts():
    result = {}

    codeql(
      'database', 'run-queries',
      '--search-path', ql_searchpath,
      '--threads', '0',
      '--rerun',
      dbpath,
      join(
        debug_pack_path,
        'source-and-sink-counts.qls'
      )
    )

    for qlf in glob.glob(join(
      debug_pack_path,
      'source-and-sink-counts',
      '*',
      'query.ql'
    )):
      relqlf = relpath(qlf, here)
      bqrsf = join(
        dbpath,
        'results',
        change_ext('.ql', '.bqrs', relqlf)
      )
      csvf = change_ext('.bqrs', '.csv', bqrsf)
      codeql(
        'bqrs', 'decode',
        '--no-titles',
        '--format', 'csv',
        '--output', csvf,
        bqrsf
      )

      with open(csvf, 'r') as f:
        for row in csv.reader(f):
          nodetype = row[0]
          count = row[1]
          if nodetype in result:
            raise Exception('Duplicated node type "' + nodetype + '"!')
          result[nodetype] = count

      remove(csvf)

    return result


  def get_sources_and_sinks():
    result = {}
    sources_and_sinks_csv = join(outdir, 'sources_and_sinks_' + lang + '.csv')
    codeql(
      'database', 'analyze',
      '--search-path', ql_searchpath,
      '--output', sources_and_sinks_csv,
      '--format', 'csv',
      '--threads', '0',
      '--rerun',
      '--no-group-results',
      dbpath,
      join(
        debug_pack_path,
        'sources-and-sinks.qls'
      )
    )

    with open(sources_and_sinks_csv, 'r') as f:
      for row in csv.reader(f):
        nodetype = row[3]
        fname = row[4]
        startline = row[5]
        startcol = row[6]
        endline = row[7]
        endcol = row[8]
        if nodetype not in result:
          result[nodetype] = []
        result[nodetype].append((fname, startline, endline))

    remove(sources_and_sinks_csv)
    return result


  def get_analysis_runs():
    PATTERN_QUERY_EVAL_TIME = re.compile('execute queries> \[(\d+)/(\d+) eval (((\d+)h)?((\d+)m)?((\d+(\.\d+)?)s|(\d+)ms))] Evaluation done; writing results to (.*\.bqrs).')
    result = []
    for eq in glob.glob(join(logdir, 'execute-queries-*')):
      d = datetime.strptime(basename(eq).split('-')[2], '%Y%m%d.%H%M%S.%f')
      with open(eq) as f:
        qdurations = []
        for m in PATTERN_QUERY_EVAL_TIME.findall(f.read()):
          idx = m[0]
          num_queries = m[1]
          hours = int(m[4]) if m[4] else 0
          minutes = int(m[6]) if m[6] else 0
          seconds = float(m[8]) if m[8] else 0
          milliseconds = int(m[10]) if m[10] else 0
          query = change_ext('.bqrs', '.ql', m[11])
          pattern = m[2]
          duration = int(milliseconds + 1000 * (seconds + 60 * (minutes + 60 * hours)))
          qdurations.append((query, duration, pattern, idx))

        qdurations = sorted(qdurations, key=lambda e: e[1], reverse=True)
        result.append((eq, d, qdurations))

    return sorted(result, key=lambda e: e[1], reverse=True)


  dependencies = get_dependencies()
  runs = get_analysis_runs()
  node_counts = get_source_and_sink_counts()
  nodes = get_sources_and_sinks()
  sorted_node_types = sorted([n for n in node_counts])


  with open(join(outdir, lang + '.html'), 'w') as f:
    f.write('<html>\n<body>\n')

    # sources and sinks
    f.write('<h1>Summary of Sources and Sinks</h1>\n')
    f.write('<table>\n')
    f.write('<tr>\n')
    f.write('  <th align="left">Type</th>\n')
    f.write('  <th align="left">Count</th>\n')
    f.write('</tr>\n')

    for n in sorted_node_types:
      detail_file = join(detail_dir, make_key(n) + '.html')

      f.write('<tr>\n')
      f.write('  <td><a href="{relpath}">{nodetype}</a></td>\n'.format(
        relpath=relpath(detail_file, outdir),
        nodetype=n
      ))
      f.write('  <td>{count}</td>\n'.format(count=str(node_counts[n])))
      f.write('</tr>\n')

      with open(detail_file, 'w') as df:
        df.write('<html>\n<body>\n')
        df.write('<h2>{nodetype} (code-only results)</h2>\n'.format(nodetype=n))
        for r in nodes.get(n, []):
          df.write(
            '<a href="{serverurl}/{repo_id}/blob/{sha}{fname}/#L{startline}-L{endline}">{fname}:{startline}</a><br>\n'.format(
              serverurl=server_url,
              repo_id=repo_id,
              sha=sha,
              fname=r[0],
              startline=r[1],
              endline=r[2]
            )
          )
        df.write('</body>\n</html>\n')

    f.write('</table>\n')

    # dependencies
    f.write('<h1>Dependencies</h1>\n')
    f.write('<table>\n')
    f.write('<tr>\n')
    f.write('  <th align="left">Name</th>\n')
    f.write('  <th align="left">#References</th>\n')
    f.write('</tr>\n')

    for d in dependencies:
      f.write('<tr>\n')
      f.write('  <td>{name}</td>\n'.format(name=d[0]))
      f.write('  <td>{count}</td>\n'.format(count=d[1]))
      f.write('</tr>\n')

    f.write('</table>\n')

    # analysis runs
    f.write('<h1>Analyses</h1>\n')
    f.write('<ul>\n')
    for fname, date, qdurations in runs:
      duration_file = join(detail_dir, make_key(fname + str(date)) + '.html')

      f.write(
        '<li><b><a href="{duration_file}">{date}</a></b> (<a href="{log_file}">{logname}</a>)</li>\n'.format(
          duration_file=relpath(duration_file, outdir),
          date=str(date),
          log_file=relpath(fname, outdir),
          logname=relpath(fname, logdir)
        )
      )

      with open(duration_file, 'w') as df:
        df.write('<html>\n<body><ol>\n')
        for query, duration, pattern, idx in qdurations:
          df.write('<li>{query} (<b>duration: {duration}</b>) (<b>index: {index}</b>)</li>\n'.format(
            query=query,
            duration=pattern,
            index=idx
          ))
        df.write('</ol></body>\n</html>\n')

    f.write('</ul>\n')

    # log files
    f.write('<h1>Log Files</h1>\n')
    f.write('<table>\n')
    f.write('<tr>\n')
    f.write('  <th align="left">File</th>\n')
    f.write('</tr>\n')
    for logf in sorted(glob.glob(join(logdir, '**'), recursive=True)):
      if isfile(logf):
        rel_logf = relpath(logf, outdir)
        name = relpath(logf, logdir)

        f.write('<tr>\n')
        f.write('  <td><a href="{relpath}">{name}</a></td>\n'.format(
          relpath=rel_logf,
          name=name
        ))
        f.write('</tr>\n')

    f.write('</table>\n')
    f.write('</body>\n</html>\n')
'''


def main(args):
  parser = argparse.ArgumentParser(
    prog='debug'
  )
  parser.add_argument(
    '--codeql-path',
    help='Path to the CodeQL executable',
    required=True
  )
  parser.add_argument(
    '--output-dir',
    help='The output directory for the debug report',
    required=True
  )
  parser.add_argument(
    '--search-path',
    help='CodeQL search path for packs',
    required=False,
    default=None
  )
  parser.add_argument(
    '--threads',
    help='Number of threads used for the analysis',
    required=False,
    default='1'
  )
  parser.add_argument(
    '--ram',
    help='RAM used for the analysis',
    required=False,
    default='0'
  )
  parser.add_argument(
    '--repo-url',
    help='Https repository url',
    required=False,
    default=None
  )
  parser.add_argument(
    'db_path',
    help='Path to the CodeQL database'
  )
  debug(parser.parse_args(args))
