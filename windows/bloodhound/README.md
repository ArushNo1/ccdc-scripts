# BloodHound CE Python collector

Run on the disposable Linux VM with network access to `umd.local` and its DNS
server, `192.168.1.182`. Requires Python 3 with `venv` and pip support.

```bash
./setup.sh
./collect.sh
```

Enter the domain administrator password at the prompt. The collection command is:

```bash
bloodhound-ce-python -u administrator -d umd.local -ns 192.168.1.182
```

The collector and all Python dependencies install into `bloodhound/.venv`.
The pip cache stays in `bloodhound/.cache/pip`. Python itself is a system
prerequisite. Results go into `bloodhound/output`; dependencies, caches, results,
and credential files are ignored by Git. Do not add passwords to these scripts.

Additional collector flags can be passed to `collect.sh`, for example
`./collect.sh --zip`. Without additional flags, the requested command's default
collection methods are used.

This installs the CE Python collector, not the BloodHound web application or its
database. Upload collected results to your existing BloodHound CE instance.

Upstream installation and usage:
https://github.com/dirkjanm/BloodHound.py/tree/bloodhound-ce
