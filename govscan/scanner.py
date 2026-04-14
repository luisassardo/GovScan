#!/usr/bin/env python3
"""GovScan v1.0 — Government Website Security Scanner (proxy-compatible)"""
import json, csv, os, time, datetime
import concurrent.futures
from urllib.parse import urlparse
from dataclasses import dataclass, field, asdict
import requests, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 20; MAX_WORKERS = 10
UA = "GovScan/1.0 (Government Website Security Audit)"

SEC_HEADERS = {
    "strict-transport-security":  {"n":"HSTS","w":15},
    "content-security-policy":    {"n":"CSP","w":15},
    "x-frame-options":            {"n":"X-Frame-Options","w":10},
    "x-content-type-options":     {"n":"X-Content-Type-Options","w":10},
    "referrer-policy":            {"n":"Referrer-Policy","w":5},
    "permissions-policy":         {"n":"Permissions-Policy","w":5},
    "x-xss-protection":           {"n":"X-XSS-Protection","w":3},
}
DANGER_HDRS = ["x-powered-by","x-aspnet-version","x-aspnetmvc-version","x-generator"]

@dataclass
class R:
    institution:str=""; acronym:str=""; category:str=""; branch:str=""
    original_url:str=""; domain:str=""
    reachable:bool=False; http_status:int=0; final_url:str=""
    redirect_chain:list=field(default_factory=list)
    ssl_works:bool=False; ssl_verified:bool=False; ssl_error:str=""
    ssl_score:int=0; ssl_grade:str="F"
    uses_https:bool=False; http_to_https:bool=False; https_enforced:bool=False
    server:str=""; powered_by:str=""; tech:list=field(default_factory=list)
    h_present:dict=field(default_factory=dict)
    h_missing:list=field(default_factory=list)
    h_values:dict=field(default_factory=dict)
    info_disc:list=field(default_factory=list)
    h_score:int=0; score:int=0; grade:str="F"
    scan_time:float=0.0; errors:list=field(default_factory=list)

def dom(url):
    if not url: return ""
    if not url.startswith(("http://","https://")): url="https://"+url
    return urlparse(url).hostname or ""

def gr(s):
    if s>=85: return "A"
    if s>=70: return "B"
    if s>=55: return "C"
    if s>=40: return "D"
    if s>=25: return "E"
    return "F"

def detect_tech(h):
    t=[]
    sv=h.get("server","").lower(); pw=h.get("x-powered-by","").lower()
    gn=h.get("x-generator","").lower(); lk=h.get("link","").lower()
    if "apache" in sv: t.append("Apache")
    if "nginx" in sv: t.append("Nginx")
    if "iis" in sv: t.append("IIS")
    if "cloudflare" in sv: t.append("Cloudflare")
    if "litespeed" in sv: t.append("LiteSpeed")
    if "varnish" in h.get("via","").lower(): t.append("Varnish")
    if "php" in pw: t.append(f"PHP")
    if "asp.net" in pw: t.append("ASP.NET")
    if "wordpress" in gn or "wp-json" in lk: t.append("WordPress")
    if "drupal" in gn or h.get("x-drupal-cache"): t.append("Drupal")
    if "joomla" in gn: t.append("Joomla")
    return t

def proc_hdrs(r, resp):
    h={k.lower():v for k,v in resp.headers.items()}
    r.server=h.get("server",""); r.powered_by=h.get("x-powered-by","")
    r.tech=detect_tech(h)
    for hk,hi in SEC_HEADERS.items():
        p=hk in h; r.h_present[hk]=p
        if p: r.h_values[hk]=h[hk]
        else: r.h_missing.append(hi["n"])
    for dh in DANGER_HDRS:
        if dh in h: r.info_disc.append(f"{dh}: {h[dh]}")

def scan_site(entry):
    t0=time.time(); url=entry.get("url",""); domain=dom(url)
    r=R(institution=entry.get("institution",""),acronym=entry.get("acronym",""),
        category=entry.get("category",""),branch=entry.get("branch",""),
        original_url=url,domain=domain)
    if not url:
        r.errors.append("No URL"); r.scan_time=round(time.time()-t0,2); return r
    tag=r.acronym or r.institution[:25]
    print(f"  [{tag}] {domain}...",end="",flush=True)
    if not url.startswith(("http://","https://")): url="https://"+url
    hu=url.replace("http://","https://") if url.startswith("http://") else url
    ht=url.replace("https://","http://") if url.startswith("https://") else url
    s=requests.Session(); s.headers["User-Agent"]=UA
    # HTTPS verified
    try:
        rp=s.get(hu,timeout=TIMEOUT,verify=True,allow_redirects=True)
        r.ssl_works=True; r.ssl_verified=True; r.reachable=True
        r.http_status=rp.status_code; r.final_url=rp.url
        r.uses_https=rp.url.startswith("https://")
        if rp.history: r.redirect_chain=[x.url for x in rp.history]
        proc_hdrs(r,rp)
    except requests.exceptions.SSLError as e:
        r.ssl_error=str(e)[:200]
        try:
            rp=s.get(hu,timeout=TIMEOUT,verify=False,allow_redirects=True)
            r.ssl_works=True; r.ssl_verified=False; r.reachable=True
            r.http_status=rp.status_code; r.final_url=rp.url
            r.uses_https=rp.url.startswith("https://")
            if rp.history: r.redirect_chain=[x.url for x in rp.history]
            proc_hdrs(r,rp)
        except Exception as e2: r.errors.append(f"HTTPS-nv:{str(e2)[:80]}")
    except requests.exceptions.ConnectionError as e: r.errors.append(f"HTTPS-conn:{str(e)[:80]}")
    except requests.exceptions.Timeout: r.errors.append("HTTPS-timeout")
    except Exception as e: r.errors.append(f"HTTPS:{str(e)[:80]}")
    # HTTP redirect check
    if not r.reachable or not r.http_to_https:
        try:
            rh=s.get(ht,timeout=12,verify=False,allow_redirects=True)
            if not r.reachable:
                r.reachable=True; r.http_status=rh.status_code; r.final_url=rh.url
                r.uses_https=rh.url.startswith("https://"); proc_hdrs(r,rh)
            if rh.url.startswith("https://"): r.http_to_https=True
        except: pass
    r.https_enforced=r.uses_https and r.http_to_https
    # Score
    if r.ssl_works and r.ssl_verified: r.ssl_score=80
    elif r.ssl_works: r.ssl_score=30
    if r.https_enforced: r.ssl_score=min(r.ssl_score+20,100)
    r.ssl_grade=gr(r.ssl_score)
    hs=0
    if r.reachable and r.http_status and r.http_status<500: hs+=5
    if r.uses_https: hs+=10
    if r.http_to_https: hs+=10
    for hk,hi in SEC_HEADERS.items():
        if r.h_present.get(hk): hs+=hi["w"]
    if r.info_disc: hs-=3*len(r.info_disc)
    r.h_score=max(0,min(hs,100))
    r.score=int(r.ssl_score*0.45+r.h_score*0.55)
    r.grade=gr(r.score)
    r.scan_time=round(time.time()-t0,2)
    print(f" SSL:{r.ssl_grade} H:{r.h_score} →{r.grade}({r.score}) [{r.scan_time}s]",flush=True)
    return r

def load_inv(p):
    import openpyxl
    wb=openpyxl.load_workbook(p,read_only=True); ws=wb.active; es=[]
    for row in ws.iter_rows(min_row=2,values_only=True):
        if not row or not row[5]: continue
        es.append({"id":row[0],"institution":row[1] or "","acronym":row[2] or "",
                    "category":row[3] or "","branch":row[4] or "","url":row[5] or "","ds":row[6] or ""})
    wb.close(); return es

def save(results, od):
    os.makedirs(od,exist_ok=True)
    ts=datetime.datetime.now(datetime.UTC).strftime("%Y%m%d_%H%M%S")
    jp=os.path.join(od,f"govscan_{ts}.json")
    with open(jp,"w",encoding="utf-8") as f:
        json.dump([asdict(r) for r in results],f,indent=2,ensure_ascii=False,default=str)
    cp=os.path.join(od,f"govscan_{ts}.csv")
    with open(cp,"w",newline="",encoding="utf-8") as f:
        w=csv.writer(f)
        w.writerow(["institution","acronym","category","branch","domain","score","grade",
                     "ssl_score","ssl_grade","ssl_works","ssl_verified","ssl_error",
                     "http_status","uses_https","http_to_https","https_enforced",
                     "server","powered_by","technology",
                     "hsts","csp","xframe","xcontent","referrer","permissions","xss",
                     "headers_score","missing_count","info_disclosure","final_url","errors"])
        for r in results:
            w.writerow([r.institution,r.acronym,r.category,r.branch,r.domain,
                r.score,r.grade,r.ssl_score,r.ssl_grade,r.ssl_works,r.ssl_verified,r.ssl_error,
                r.http_status,r.uses_https,r.http_to_https,r.https_enforced,
                r.server,r.powered_by,";".join(r.tech),
                r.h_present.get("strict-transport-security",False),
                r.h_present.get("content-security-policy",False),
                r.h_present.get("x-frame-options",False),
                r.h_present.get("x-content-type-options",False),
                r.h_present.get("referrer-policy",False),
                r.h_present.get("permissions-policy",False),
                r.h_present.get("x-xss-protection",False),
                r.h_score,len(r.h_missing),";".join(r.info_disc),r.final_url,
                ";".join(r.errors) if r.errors else ""])
    return jp,cp

def summary(results):
    total=len(results)
    if not total: return
    print(f"\n{'='*65}\n  GOVSCAN RESULTS — {total} sites\n{'='*65}")
    gm={}
    for r in results: gm[r.grade]=gm.get(r.grade,0)+1
    print(f"\n  Grade Distribution:")
    for g in ["A","B","C","D","E","F"]:
        c=gm.get(g,0); pct=c/total*100; bar="█"*int(pct/2)
        print(f"    {g} │ {bar} {c} ({pct:.0f}%)")
    rc=[r for r in results if r.reachable]; rt=len(rc)
    if not rt: print("  No reachable sites!"); return
    avg=sum(r.score for r in rc)/rt
    print(f"\n  Key Findings ({rt} reachable of {total}):")
    print(f"    Average score:          {avg:.1f}/100")
    print(f"    Unreachable:            {total-rt}/{total}")
    ns=sum(1 for r in results if not r.ssl_works)
    bc=sum(1 for r in results if r.ssl_works and not r.ssl_verified)
    nh=sum(1 for r in rc if not r.uses_https)
    nr=sum(1 for r in rc if not r.http_to_https)
    print(f"    No SSL:                 {ns}/{total}")
    print(f"    Invalid SSL cert:       {bc}/{total}")
    print(f"    Not using HTTPS:        {nh}/{rt}")
    print(f"    No HTTP→HTTPS:          {nr}/{rt}")
    for hk,hi in SEC_HEADERS.items():
        miss=sum(1 for r in rc if not r.h_present.get(hk))
        print(f"    Missing {hi['n']:22s} {miss}/{rt} ({miss/rt*100:.0f}%)")
    il=sum(1 for r in rc if r.info_disc)
    print(f"    Info disclosure:        {il}/{rt}")
    # Tech
    techs={}
    for r in rc:
        for t in r.tech: techs[t]=techs.get(t,0)+1
    if techs:
        print(f"\n  Technology Stack:")
        for t,c in sorted(techs.items(),key=lambda x:-x[1])[:12]:
            print(f"    {t:20s} {c:3d} ({c/rt*100:.0f}%)")
    print(f"\n  Bottom 15:")
    for r in results[:15]:
        m="⚠" if r.ssl_works and not r.ssl_verified else("✗" if not r.ssl_works else " ")
        print(f"    {r.score:3d}/100 [{r.grade}]{m} {r.acronym or r.institution[:28]:28s} {r.domain}")
    print(f"\n  Top 10:")
    for r in sorted(results,key=lambda x:-x.score)[:10]:
        print(f"    {r.score:3d}/100 [{r.grade}]  {r.acronym or r.institution[:28]:28s} {r.domain}")
    dg=[r for r in results if "digecam" in(r.domain or"").lower() or "DIGECAM" in r.acronym]
    md=[r for r in results if "mindef" in(r.domain or"").lower() or "MINDEF" in r.acronym]
    if dg or md:
        print(f"\n  ── DIGECAM / MINDEF Spotlight ──")
        for r in dg+md:
            print(f"    {r.acronym}: score={r.score} ssl={r.ssl_grade} "
                  f"hsts={'Y' if r.h_present.get('strict-transport-security') else 'N'} "
                  f"csp={'Y' if r.h_present.get('content-security-policy') else 'N'} "
                  f"tech={','.join(r.tech)}")
    print(f"\n{'='*65}")

def run(inv,od="results",br=None,mx=None,wk=MAX_WORKERS):
    print(f"\n{'='*65}")
    print(f"  GovScan v1.0 — SSL/TLS + HTTP Security Headers")
    print(f"  {datetime.datetime.now(datetime.UTC).isoformat()}Z")
    print(f"{'='*65}")
    es=load_inv(inv)
    print(f"\n→ {len(es)} sites loaded")
    if br: es=[e for e in es if e["branch"].lower()==br.lower()]; print(f"  Filtered: {len(es)} ({br})")
    if mx: es=es[:mx]; print(f"  Limited: {mx}")
    print(f"\n→ Scanning ({wk} workers)...\n")
    rs=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=wk) as pool:
        fs={pool.submit(scan_site,e):e for e in es}
        for f in concurrent.futures.as_completed(fs):
            try: rs.append(f.result())
            except Exception as e: print(f"  [ERR] {fs[f]['institution']}: {e}")
    rs.sort(key=lambda x:x.score)
    jp,cp=save(rs,od)
    summary(rs)
    print(f"\n→ JSON: {jp}\n→ CSV:  {cp}")
    return rs

if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument("inventory"); p.add_argument("-o","--output",default="results")
    p.add_argument("-b","--branch",default=None); p.add_argument("-n","--max",type=int,default=None)
    p.add_argument("-w","--workers",type=int,default=MAX_WORKERS)
    a=p.parse_args(); run(a.inventory,a.output,a.branch,a.max,a.workers)
