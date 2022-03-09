import argparse
import util
import os
from os.path import dirname, isfile, abspath, join, basename
import sys
import ghlib


def upload(args):
  git = util.Git('.')
  gh = ghlib.GitHub('https://api.github.com', os.environ['GITHUB_TOKEN'])
  repo = gh.getRepo(args.repo_id)
  repo.upload_latest(git.branch(), git.revision(git.branch()), args.dist)


def inject(args):
  args.script = abspath(args.script)
  args.dist = abspath(args.dist)
  args.output = abspath(args.output)
  scriptdir = dirname(args.script)

  if not isfile(args.script):
    util.error('Given script "%s" does not exist!' % (args.script))

  os.chdir(scriptdir)
  util.info('Working directory is "%s"!' % (scriptdir))

  git = util.Git(scriptdir)
  inputdist = util.extract_dist(args.dist)
  customization_hash = util.hashstr(
    util.sha1sumd(inputdist) +
    git.revision(git.branch())
  )
  if customization_hash != util.get_customization_hash(args.output):
    util.info('Customization hashes of input and output differ. Recreating output...')
  else:
    util.info('Customization hashes of input and output match. Nothing to do!')
    return

  # execute the user's script
  from importlib import import_module
  sys.path.append(scriptdir)
  m = import_module(basename(args.script).rsplit('.', 1)[0])
  customize = getattr(m, 'customize')
  customize(util.ScriptUtils(inputdist))

  util.info('Writing customization hash ...')
  util.write_str(join(inputdist, 'customization_hash'), customization_hash)
  util.info('Creating output archive "%s"...' % (args.output))
  util.tar_czf(inputdist, args.output)


def main():
  parser = argparse.ArgumentParser(prog="customize")
  subparsers = parser.add_subparsers()

  # inject
  inject_parser = subparsers.add_parser(
    'inject',
    help='Inject customizations into a CodeQL distribution',
    description='Inject customizations into a CodeQL distribution',
  )
  inject_parser.add_argument(
    '--dist',
    required=True,
    help='A .zip, .tar.gz or directory containing a CodeQL distribution',
  )
  inject_parser.add_argument(
    '--output',
    required=True,
    help='The file to which to output the customized distribution (a .tar.gz archive)',
  )
  inject_parser.add_argument(
    '--script',
    required=True,
    help='A python file with the customization script. It should contain a function "customize()" which takes a "Utils" object as a single parameter',
  )
  inject_parser.set_defaults(func=inject)

  # upload
  upload_parser = subparsers.add_parser(
    'upload',
    help='Upload a customized distribution as a release, using the GitHub REST API',
    description='Upload a customized CodeQL distribution as a release, using the GitHub REST API',
  )
  upload_parser.add_argument(
    '--dist',
    required=True,
    help='A .tar.gz file containing a CodeQL distribution',
  )
  upload_parser.add_argument(
    '--repo-id',
    required=True,
    help='The repository id in the format of "orgoruser/reponame"',
  )
  upload_parser.set_defaults(func=upload)

  def print_usage(args):
    print(parser.format_usage())

  parser.set_defaults(func=print_usage)
  args = parser.parse_args()

  # run the given action
  args.func(args)


main()
