# CodeQL Debug Action

The aim of this action is to give users a report about a CodeQL database to aid in debugging of situations where "no results were found" / only a few with the standard Code Scanning security queries.

Ideally, a seasoned CodeQL engineer prefers to have the actual database itself, which contains almost everything they could ask for. However, a) not everyone has this level of expertise and b) it might not be possible to get access to the database, e.g. when the code is proprietary and can't leave the premises. In those cases we want to extract information from the database which is not considered sensitive and can help narrow down the problems.

This action extracts such information and generates an html report.


# Example report

[This is what it looks like](example-report.html).


# Setup

To get this report for your database, you have to add the action to your workflow as well as upload the output. Make sure you add the action _after_ you have run the `github/codeql-action/analyze` action, like so:

```yaml
name: "CodeQL Debug Report Test"

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '34 3 * * 6'

jobs:
  analyze:
    name: Analyze
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write

    strategy:
      fail-fast: false
      matrix:
        language: [ 'javascript' ]

    steps:
    - name: Checkout repository
      uses: actions/checkout@v2

    - name: Initialize CodeQL
      id:   codeqltoolchain
      uses: github/codeql-action/init@v1
      with:
        languages: ${{ matrix.language }}

    - name: Autobuild
      uses: github/codeql-action/autobuild@v1

    - name: Perform CodeQL Analysis
      uses: github/codeql-action/analyze@v1

    ### insert the following two actions #########
    - name: CodeQL Debug Report
      uses: zbazztian/codeql-tools/debug@main

    - name: Upload loc as a Build Artifact
      uses: actions/upload-artifact@v2.2.0
      with:
        name: codeql-debug-report
        path: codeql-debug-report
    ##############################################
```

# Options

Documented [here](action.yml).
