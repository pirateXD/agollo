package fingerprint

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// reportAK 是 SLS AccessKey，格式 "AccessKeyID:AccessKeySecret"。占位变量，
// deploy-time 由外围服务注入真实值（占位符 REPORT_AK_*）。
var reportAK = ""

// reportLogstore 是 SLS logstore 名，占位变量，deploy-time 注入真实值
// （占位符 REPORT_LOGSTORE）。
var reportLogstore = ""

// putLogsFn 是上报的 seam：真实实现为 defaultPutLogs，测试注入 fake 以隔离网络。
var putLogsFn = defaultPutLogs

// sleepFn 是重试退避的 sleep seam：真实实现为 time.Sleep，测试替换为无操作。
var sleepFn = time.Sleep

// ReportToSLS 把 rep 校验、组装后经 putLogsFn 上报到 SLS。它自身不做网络 IO：
// 先解析 reportAK 校验 AccessKey 格式，再取 ResolveReportAddrs() 的第一个地址
// 作为 endpoint（空则返回 error），最后把 (endpoint, reportAK, rep) 交给 putLogsFn。
func ReportToSLS(rep Report) error {
	parts := strings.SplitN(reportAK, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return errors.New("fingerprint: malformed reportAK, want \"AccessKeyID:AccessKeySecret\"")
	}

	addrs := ResolveReportAddrs()
	if len(addrs) == 0 || addrs[0] == "" {
		return errors.New("fingerprint: no report address configured")
	}

	return putLogsFn(addrs[0], reportAK, rep)
}

// ReportAsync 异步上报：不阻塞调用方，且吞掉一切 panic。
func ReportAsync(rep Report) {
	go func() {
		defer func() { _ = recover() }()
		_ = retryReport(rep)
	}()
}

// retryReport 最多调 ReportToSLS 3 次，间隔 1s/2s/4s（指数退避），任一成功即返回。
// 退避用 sleepFn 以便测试替换为无操作。
func retryReport(rep Report) error {
	backoff := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}
	var lastErr error
	for i := 0; i < 3; i++ {
		if i > 0 {
			sleepFn(backoff[i-1])
		}
		if err := ReportToSLS(rep); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return lastErr
}

// signRequest 按 SLS 官方签名算法计算 HMAC-SHA1 签名并 base64。确定性：无随机数、
// 无当前时间依赖（Date 由调用方经 headers 注入）。AccessKeySecret 从 reportAK 解析。
//
//	stringToSign = method + "\n" + Content-MD5 + "\n" + Content-Type + "\n" +
//	               Date + "\n" + canonicalizedSLSHeaders + resource
//
// canonicalizedSLSHeaders 是全部 x-log-* / x-acs-* 头按 key（小写）字典序排列，
// 每项 "key:value\n"，value 去除两端空白。
func signRequest(method string, headers map[string]string, resource string) string {
	secret := ""
	if parts := strings.SplitN(reportAK, ":", 2); len(parts) == 2 {
		secret = parts[1]
	}

	type kv struct{ k, v string }
	var pairs []kv
	for k, v := range headers {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-log-") || strings.HasPrefix(lk, "x-acs-") {
			pairs = append(pairs, kv{lk, strings.TrimSpace(v)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].k < pairs[j].k })

	var sb strings.Builder
	for _, p := range pairs {
		sb.WriteString(p.k)
		sb.WriteString(":")
		sb.WriteString(p.v)
		sb.WriteString("\n")
	}

	stringToSign := method + "\n" +
		headers["Content-MD5"] + "\n" +
		headers["Content-Type"] + "\n" +
		headers["Date"] + "\n" +
		sb.String() +
		resource

	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// defaultPutLogs 是真实上报实现：向 endpoint 的 SLS PutLogs 端点发 HTTP PUT，
// body 为 Report 的 JSON。签名经 signRequest 计算后放入 Authorization 头。
func defaultPutLogs(endpoint, ak string, rep Report) error {
	parts := strings.SplitN(ak, ":", 2)
	if len(parts) != 2 || parts[0] == "" {
		return errors.New("fingerprint: malformed reportAK")
	}
	accessKeyID := parts[0]

	body, err := json.Marshal(rep)
	if err != nil {
		return err
	}

	date := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
	resource := "/logstores/" + reportLogstore + "/shards/lb"

	headers := map[string]string{
		"Content-MD5":           "",
		"Content-Type":          "application/json",
		"Date":                  date,
		"x-log-apiversion":      "0.6.0",
		"x-log-signaturemethod": "hmac-sha1",
		"x-log-bodyrawsize":     fmt.Sprintf("%d", len(body)),
	}
	signature := signRequest(http.MethodPut, headers, resource)

	req, err := http.NewRequest(http.MethodPut, endpoint+resource, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Date", date)
	req.Header.Set("x-log-apiversion", "0.6.0")
	req.Header.Set("x-log-signaturemethod", "hmac-sha1")
	req.Header.Set("x-log-bodyrawsize", fmt.Sprintf("%d", len(body)))
	req.Header.Set("Authorization", "LOG "+accessKeyID+":"+signature)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("fingerprint: SLS PutLogs returned status %d", resp.StatusCode)
	}
	return nil
}
