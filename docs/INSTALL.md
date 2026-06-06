# Installing RelayX

RelayX is packaged as a Python console application.

## Local Development

```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
relayx --version
```

## pipx

From a local checkout:

```bash
pipx install .
relayx --version
```

From GitHub:

```bash
pipx install git+https://github.com/RedteamNotes/RelayX.git
relayx --version
```

## Release Checklist

1. Update `relayx.__version__` and `pyproject.toml`.
2. Run the full unit test suite.
3. Run the RelayX quality gate.
4. Review [`docs/INTEGRATION_TESTS.md`](INTEGRATION_TESTS.md) when lab fixtures
   or protocol classifications changed.
5. Build a wheel and source distribution.
6. Smoke-test the generated wheel.
7. Tag the release in GitHub.

```bash
python3 -m unittest discover -s tests
relayx -q quality-gate -C . -f json -o relayx-quality-gate.json
relayx schema validate -k quality-gate relayx-quality-gate.json
python3 -m build
python3 -m pip install --force-reinstall dist/relayx-*.whl
relayx --no-banner --version
```

The GitHub CI workflow runs unit tests, `relayx quality-gate`, wheel build, and
wheel install smoke tests. The release workflow repeats those checks and
verifies that `v*` tags match the package version.
