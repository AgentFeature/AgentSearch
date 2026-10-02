#!/usr/bin/env python3
"""Local end-to-end acceptance checks for the AgentSearch binaries.

The script builds the four commands into a temporary directory, then exercises the
CLI, the authenticated HTTP API, continuous watch and the corpus tool against a
loopback origin. It makes no external network requests and requires no credentials:
the API bearer token is generated at runtime and never printed. It is not part of
`go test`; run it explicitly for a release check:

    python3 tests/smoke.py
"""
import json,os,pathlib,re,secrets,signal,subprocess,sys,tempfile,threading,time,urllib.request,urllib.error,http.server,socketserver,shutil

REPO=pathlib.Path(__file__).resolve().parents[1]
BUILD=pathlib.Path(tempfile.mkdtemp(prefix="agentsearch-smoke-build-"))
for command in ("agentsearch","agentsearch-server","agentsearch-corpus","convert"):
    subprocess.run(["go","build","-o",str(BUILD/command),"./cmd/"+command],cwd=str(REPO),check=True)
BIN=str(BUILD/"agentsearch"); SERVER=str(BUILD/"agentsearch-server"); CORPUS=str(BUILD/"agentsearch-corpus")
root=pathlib.Path(tempfile.mkdtemp(prefix="agentsearch-smoke-run-")); shutil.rmtree(root,ignore_errors=True); (root/"www").mkdir(parents=True); (root/"out").mkdir()
(root/"www"/"index.html").write_text("<html><body>smoke origin</body></html>")
# A 200 profile page for the smoke target: a 404 that matches no detection
# rule is a source error, not a found profile.
(root/"www"/"smoke_audit_target").write_text("<html><body>member profile</body></html>")
class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self,*a,**k): super().__init__(*a,directory=str(root/"www"),**k)
    def log_message(self,*a): pass
origin=socketserver.TCPServer(("127.0.0.1",0),Handler); origin_port=origin.server_address[1]
threading.Thread(target=origin.serve_forever,daemon=True).start()
sites=root/"sites.yaml"
sites.write_text(f"- name: SmokeOrigin\n  url: \"http://127.0.0.1:{origin_port}/{{username}}\"\n  check_type: message\n  absence_strs: [\"smoke origin\"]\n")
watch=root/"watchlist.yaml"; watch.write_text("targets:\n  - type: username\n    value: smoke_audit_target\n")
def run(args,cwd=str(root),env=None,timeout=120):
    return subprocess.run([BIN]+args,cwd=cwd,capture_output=True,text=True,timeout=timeout,env=env)
results={}
# 1. help and invalid input
for label,args,want in [("help",["-h"],0),("no-target",[],1),("bad-bitcoin",["-bitcoin","not-an-address"],1),("bad-txid",["-bitcoin-tx","zz"],1),("bad-combo",["-domain","example.com","-w","10"],1),("bad-format",["-u","x","-of","exe"],1),("watch-option-without-file",["-u","x","-watch-interval","30s"],1),("negative-retries",["-u","x","-retries","-5","-s",str(sites),"-o",str(root/"out"),"-of","json"],0)]:
    r=run(args); results[label]=r.returncode
    assert r.returncode==want, (label,r.returncode,r.stdout[-300:],r.stderr[-300:])
help_out=run(["-h"]); assert "Usage: agentsearch" in (help_out.stdout+help_out.stderr), help_out.stdout[-200:]
# 2. full six-format report for a configured source
r=run(["-u","smoke_audit_target","-s",str(sites),"-o",str(root/"out"),"-of","json,csv,txt,html,pdf,docx","-rf","","-w","1","-rl","0s","-rt","5s","-retries","0"])
results["six-format-search"]=r.returncode
assert r.returncode==0, r.stderr[-400:]
for ext in ("json","csv","txt","html","pdf","docx"):
    path=root/"out"/f"smoke_audit_target.{ext}"; assert path.is_file() and path.stat().st_size>0, ext
legacy=json.loads((root/"out"/"smoke_audit_target.json").read_text())
assert isinstance(legacy,list) and legacy and legacy[0]["target_type"]=="username", legacy
report=json.loads((root/"out"/"smoke_audit_target_report.json").read_text())
assert report["schema"].startswith("agentsearch.report.v1") and report["results"] and report["status"] in {"complete","partial"}
assert report["summary"]["sources"]==1 and report["results"][0]["classification"]=="inferred", report["summary"]
html=(root/"out"/"smoke_audit_target.html").read_text(); assert "<script" not in html.lower() and "javascript:" not in html.lower()
# 3. legacy -rf bridge writes ./output and prints the CLI report
r=run(["-u","smoke_audit_target","-s",str(sites),"-o",str(root/"out"),"-of","","-rf","cli","-w","1","-rl","0s","-rt","5s"])
results["legacy-cli-report"]=r.returncode
assert r.returncode==0 and "AgentSearch Investigation Report" in r.stdout and (root/"output"/"smoke_audit_target_report.txt").is_file()
# 4. opt-in AI without a configured provider must not fail the run or erase evidence
r=run(["-u","smoke_audit_target","-s",str(sites),"-o",str(root/"ai-out"),"-of","json","-rf","","-w","1","-rl","0s","-rt","5s","-ai"])
results["ai-not-configured"]=r.returncode
ai=json.loads((root/"ai-out"/"smoke_audit_target_report.json").read_text())
assert r.returncode==0 and ai["analysis"]["status"]=="failed" and ai["analysis"]["error_code"] in {"ai_disabled","ai_not_configured"} and ai["results"], ai.get("analysis")
# 5. watch: initial baseline, then a restart with no changes and no spurious diff
def watch_run():
    proc=subprocess.Popen([BIN,"-watch-file",str(watch),"-watch-state-dir",str(root/"watch"),"-watch-interval","30s","-watch-concurrency","1","-s",str(sites),"-services","","-rt","5s","-tt","30s"],cwd=str(root),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    time.sleep(6); proc.send_signal(signal.SIGINT)
    out,err=proc.communicate(timeout=30); return proc.returncode,out,err
state=root/"watch"; state.mkdir(mode=0o700); os.chmod(state,0o700)
code,out,err=watch_run(); results["watch-cycle-1"]=code; assert code==0, err[-300:]
baselines=list((state/"state").glob("*.json")); observations=(state/"observations.jsonl").read_text().splitlines()
assert len(baselines)==1 and observations and json.loads(observations[0])["outcome"]=="baseline_created", observations[:1]
code,out,err=watch_run(); results["watch-cycle-2"]=code; assert code==0, err[-300:]
second=json.loads((state/"observations.jsonl").read_text().splitlines()[-1])
assert second["outcome"]=="unchanged" and second["change_count"]==0 and (state/"changes.jsonl").read_text()=="", second
# 6. server: health, auth, search, AI opt-in rejection/absence
token=secrets.token_urlsafe(32)
env=dict(os.environ,AGENTSEARCH_API_TOKEN=token)
proc=subprocess.Popen([SERVER,"-listen","127.0.0.1:0","-s",str(sites),"-services","","-password-backend","api","-max-concurrent","2"],cwd=str(root),env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
def call(path,payload=None,header=True,method="POST"):
    req=urllib.request.Request(f"http://127.0.0.1:{port}{path}",data=None if payload is None else json.dumps(payload).encode(),method=method)
    if payload is not None: req.add_header("Content-Type","application/json")
    if header: req.add_header("Authorization","Bearer "+token)
    try:
        with urllib.request.urlopen(req,timeout=30) as resp: return resp.status,json.loads(resp.read())
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b"{}")
# The default loopback listener uses a fixed port; use an explicit free port instead.
proc.terminate(); proc.wait(timeout=10)
import socket
s=socket.socket(); s.bind(("127.0.0.1",0)); port=s.getsockname()[1]; s.close()
proc=subprocess.Popen([SERVER,"-listen",f"127.0.0.1:{port}","-s",str(sites),"-services","","-password-backend","api","-max-concurrent","2"],cwd=str(root),env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
try:
    for _ in range(50):
        try:
            if call("/health",method="GET")[0]==200: break
        except Exception: time.sleep(0.2)
    results["api-health"]=call("/health",method="GET")[0]
    assert results["api-health"]==200
    results["api-unauthorized"]=call("/api/v1/search",{"type":"username","target":"smoke_audit_target"},header=False)[0]
    assert results["api-unauthorized"]==401
    status,body=call("/api/v1/search",{"type":"username","target":"smoke_audit_target"})
    results["api-search"]=status
    assert status==200 and body["results"], body
    status,body=call("/api/v1/search",{"type":"username","target":"smoke_audit_target","analysis":True})
    results["api-analysis-requested"]=status
    assert status==200 and body["analysis"]["status"]=="failed" and body["analysis"]["error_code"] in {"ai_disabled","ai_not_configured"}, body.get("analysis")
    results["api-invalid-type"]=call("/api/v1/search",{"type":"bogus","target":"x"})[0]
    results["api-query-rejected"]=call("/api/v1/search?x=1",{"type":"username","target":"x"})[0]
    results["api-analysis-nonbool"]=call("/api/v1/search",{"type":"username","target":"x","analysis":"yes"})[0]
    assert results["api-invalid-type"]==400 and results["api-query-rejected"]==400 and results["api-analysis-nonbool"]==400
finally:
    proc.terminate()
    try: proc.wait(timeout=15)
    except subprocess.TimeoutExpired: proc.kill()
# 7. corpus tool usage and safe failure
r=subprocess.run([CORPUS,"-h"],capture_output=True,text=True); results["corpus-help"]=r.returncode
r=subprocess.run([CORPUS,"import","-db",str(root/"corpus"),"-input","/nonexistent","-sha256","0"*64,"-acquired-at","2026-01-01T00:00:00Z","-complete"],capture_output=True,text=True); results["corpus-invalid-import"]=r.returncode
r=subprocess.run([CORPUS,"prune"],capture_output=True,text=True); results["corpus-missing-db"]=r.returncode
assert results["corpus-help"]==0 and results["corpus-invalid-import"]==1 and results["corpus-missing-db"]==1
origin.shutdown()
print(json.dumps(results,indent=2))
shutil.rmtree(root,ignore_errors=True)
shutil.rmtree(BUILD,ignore_errors=True)
print("SMOKE_OK")
