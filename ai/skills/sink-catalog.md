---
name: sink-catalog
title: Dangerous sinks by vulnerability class
---
# Skill: sink-catalog

The machine-readable version lives in `api/harness/sinks.py`; keep both in step.

| Sink id | CWE | Severity | Examples |
| --- | --- | --- | --- |
| `cmd` | CWE-78 | critical | `os.system`, `subprocess.*(shell=True)`, `child_process.exec`, `Runtime.exec`, `exec()/system()/passthru()/shell_exec()` (PHP), `exec.Command` with `sh -c` |
| `code` | CWE-94/95 | critical | `eval`, `exec` (Python), `new Function`, `vm.runIn*`, PHP `eval/assert/create_function`, `ScriptEngine.eval` |
| `sql` | CWE-89 | high | `cursor.execute` with string building, `raw()`, `.query("..."+x)`, `mysqli_query`, `Statement.execute*`, `knex.raw`, `sequelize.query` |
| `nosql` | CWE-943 | high | `$where`, `find(JSON.parse(x))`, `collection.find(req.body)` |
| `deser` | CWE-502 | critical | `pickle.loads`, `yaml.load` (unsafe), `marshal.loads`, `unserialize`, `ObjectInputStream.readObject`, `node-serialize` |
| `path` | CWE-22 | high | `open/send_file/readFile/fopen/include/require` with a built path |
| `ssrf` | CWE-918 | high | `requests.get(url)`, `urllib.urlopen`, `fetch/axios(url)`, `curl_exec`, `file_get_contents(url)` |
| `xss` | CWE-79 | medium | `render_template_string`, `Markup(...)`, `|safe`, `innerHTML`, `dangerouslySetInnerHTML`, `echo $_GET`, `res.send(user)` |
| `redirect` | CWE-601 | medium | `redirect(param)`, `res.redirect(req.query.x)`, `header("Location: ".$x)` |
| `xxe` | CWE-611 | high | `etree.parse/fromstring` with resolvers, `DocumentBuilderFactory` without hardening, `simplexml_load_string` + `LIBXML_NOENT` |
| `ldap` | CWE-90 | high | `ldap.search(filter + x)` |
| `crypto` | CWE-327/328 | low | `md5/sha1` for passwords, `DES`, `ECB`, `random` for tokens |
| `secret` | CWE-798 | medium | hard-coded passwords, API keys, private keys |
