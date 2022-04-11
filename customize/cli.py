import argparse
import util
import os
from os.path import dirname, isfile, abspath, join, basename
import sys


def inject(args):
  args.script = abspath(args.script)
  args.dist = abspath(args.dist)
  args.output = abspath(args.output)
  scriptdir = dirname(args.script)
  gitdir = scriptdir

  if not isfile(args.script):
    util.error('Given script "%s" does not exist!' % (args.script))

  os.chdir(scriptdir)
  util.info('Working directory is "%s"!' % (scriptdir))

  git = util.make_git(gitdir)
  inputdist = util.extract_dist(args.dist)
  customization_hash = util.hashstr(
    util.sha1sumd(inputdist) +
    util.git_revision(git, util.git_branch(git))
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

  util.write_str(join(inputdist, 'customization_hash'), customization_hash)
  util.tar_czf(inputdist, args.output)

#gh = GitHub('https://api.github.com', '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')
#repo = gh.getRepo('zbazztian/customized-dist')

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

  def print_usage(args):
    print(parser.format_usage())

  parser.set_defaults(func=print_usage)
  args = parser.parse_args()

  # run the given action
  args.func(args)


main()
