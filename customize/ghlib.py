import requests
import logging
import json
import util
from os.path import join
from requests import HTTPError
import mimetypes
from fnmatch import fnmatch

RESULTS_PER_PAGE = 100


def json_accept_header():
  return {"Accept": "application/vnd.github.v3+json"}


def sort_by_created_at(releasesorassets):
  return sorted(
    releasesorassets,
    key=lambda e: parse_date(e['created_at']),
    reverse=True
  )


def make_tag(branch, revision):
  return '%s-%s' % (branch, revision)


class GitHub:
  def __init__(self, url, token):
    self.url = url
    self.token = token

  def default_headers(self):
    auth = {"Authorization": "token " + self.token}
    auth.update(json_accept_header())
    return auth

  def getRepo(self, repo_id):
    return Repo(self, repo_id)


class Repo:

  def __init__(self, github, repo_id):
    self.gh = github
    self.repo_id = repo_id


  def latest_asset(tagfilter, assetfilter):
    ''' note that this will not necessarily return a file
        from the _latest_ release. It will return a file
        from the newest release which matches the given
        tagfilter and assetfilter. This is important, since
        a download would fail if someone would be in the
        process of uploading an asset, which first requires
        to create an empty release (race condition)'''
    for r in sort_by_created_at(self.list_releases()):
      if fnmatch(r['name'], tagfilter):
        for a in sort_by_created_at(r['assets']):
          if fnmatch(a['name'], assetfilter):
            return a
    return None


  def download_asset(self, asset, directory):
    headers=self.gh.default_headers()
    headers['Accept'] = 'application/octet-stream'

    with requests.get(
      "{api_url}/repos/{repo_id}/releases/assets/{asset_id}".format(
        api_url=self.gh.url,
        repo_id=self.repo_id,
        asset_id=asset['id'],
      ),
      headers=headers,
      timeout=util.REQUEST_TIMEOUT,
    ) as r:

      r.raise_for_status()

      with open(join(directory, asset['name']), 'wb') as f:
        for chunk in r.iter_content():
          if chunk:
            f.write(chunk)


  def list_releases(self):
    try:
      resp = requests.get(
        "{api_url}/repos/{repo_id}/releases?per_page={results_per_page}".format(
          api_url=self.gh.url,
          repo_id=self.repo_id,
          results_per_page=RESULTS_PER_PAGE,
        ),
        headers=self.gh.default_headers(),
        timeout=util.REQUEST_TIMEOUT,
      )

      while True:
        resp.raise_for_status()

        for r in resp.json():
          yield r

        nextpage = resp.links.get("next", {}).get("url", None)
        if not nextpage:
          break

        resp = requests.get(
          nextpage,
          headers=self.gh.default_headers(),
          timeout=util.REQUEST_TIMEOUT,
        )

    except HTTPError as httpe:
      if httpe.response.status_code == 404:
        # A 404 suggests that the repository doesn't exist
        # so we return an empty list
        pass
      else:
        # propagate everything else
        raise


  def get_release(self, tag):
    for r in self.list_releases():
      if r['tag_name'] == tag:
        return r
    return None


  def create_release(self, tag, revision):
    with requests.post(
      "{api_url}/repos/{repo_id}/releases".format(
        api_url=self.gh.url,
        repo_id=self.repo_id,
      ),
      data=json.dumps(
        {
          'tag_name': tag,
          'target_commitish': revision,
        }
      ),
      headers=self.gh.default_headers(),
      timeout=util.REQUEST_TIMEOUT,
    ) as r:

      r.raise_for_status()
      return r.json()


  def upload_asset(self, release, asset_name, filepath):
    headers=self.gh.default_headers()
    content_type = mimetypes.guess_type(filepath)[0]
    headers['Content-Type'] = 'application/octet-stream' if content_type is None else content_type

    with open(filepath, 'rb') as f:
      with requests.post(
        release['upload_url'].replace('{?name,label}', '') + "?name={name}&label=dist".format(
          name=asset_name,
        ),
        data=f,
        headers=headers,
        timeout=util.REQUEST_TIMEOUT,
      ) as r:

        r.raise_for_status()
        return r.json()


  def get_or_create_release(self, branch, revision):
    tag = make_tag(branch, revision)
    r = self.get_release(tag)
    if r is None:
      r = self.create_release(tag, revision)
    return r


  def upload_latest(self, branch, revision, filepath):
    r = self.get_or_create_release(branch, revision)
    sha = util.sha1sum(filepath)
    self.upload_asset(r, 'codeql-bundle-%s-%s.tar.gz' % (util.make_date(), sha), filepath)
