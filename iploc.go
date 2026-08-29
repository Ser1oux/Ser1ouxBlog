package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

type ipLocEntry struct {
	Location string    `json:"location"`
	Expires  time.Time `json:"expires"`
}

var (
	ipLocCache = map[string]ipLocEntry{}
	ipLocMu    sync.RWMutex

	ipHTTPClient = &http.Client{
		Timeout: 2500 * time.Millisecond,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			TLSHandshakeTimeout:   2 * time.Second,
			ResponseHeaderTimeout: 2 * time.Second,
			IdleConnTimeout:       30 * time.Second,
			MaxIdleConns:          8,
		},
	}
)

// 获取客户端真实 IP：优先公网地址，跳过反代/内网 hop。
func getClientIP(r *http.Request) string {
	var candidates []string
	// X-Real-IP 由自建 nginx 覆写为真实连接地址，优先级最高；
	// CF-Connecting-IP / True-Client-IP 直连时可被客户端伪造，仅作后备。
	for _, h := range []string{"X-Real-IP", "CF-Connecting-IP", "True-Client-IP"} {
		if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
			candidates = append(candidates, v)
		}
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for _, p := range strings.Split(xff, ",") {
			if v := strings.TrimSpace(p); v != "" {
				candidates = append(candidates, v)
			}
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		candidates = append(candidates, host)
	} else if r.RemoteAddr != "" {
		candidates = append(candidates, r.RemoteAddr)
	}

	var fallback string
	for _, raw := range candidates {
		ip := normalizeIP(raw)
		if ip == "" {
			continue
		}
		if fallback == "" {
			fallback = ip
		}
		if !isPrivateOrLocalIP(ip) {
			return ip
		}
	}
	return fallback
}

func getIPLocation(ip string) string {
	return resolveIPLocation(ip)
}

func getIPGeolocation(ip string) string {
	return resolveIPLocation(ip)
}

func resolveIPLocation(ip string) string {
	ip = normalizeIP(ip)
	if ip == "" {
		return "未知地区"
	}
	if isPrivateOrLocalIP(ip) {
		return "本地/内网"
	}

	if loc, ok := peekIPLocCache(ip); ok {
		return loc
	}

	loc := lookupIPLocationOnline(ip)
	if isUnknownLocation(loc) {
		storeIPLocCache(ip, "未知地区", 3*time.Minute)
		return "未知地区"
	}
	// 只有国家、没有省市时短缓存，方便下次再问更细的源
	if isCountryOnly(loc) {
		storeIPLocCache(ip, loc, 5*time.Minute)
		return loc
	}
	storeIPLocCache(ip, loc, 24*time.Hour)
	return loc
}

func displayLocation(stored, ip string) string {
	if ip != "" {
		if loc, ok := peekIPLocCache(ip); ok && locationScore(loc) > locationScore(stored) {
			return loc
		}
	}
	if !isUnknownLocation(stored) {
		return stored
	}
	if strings.TrimSpace(stored) == "" {
		return "未知地区"
	}
	return stored
}

func isUnknownLocation(s string) bool {
	s = strings.TrimSpace(s)
	switch strings.ToLower(s) {
	case "", "未知", "未知地区", "未知位置", "unknown", "null", "none", "n/a", "xx":
		return true
	default:
		return false
	}
}

var countryOnlyNames = map[string]bool{
	"中国": true, "中华人民共和国": true, "美国": true, "日本": true, "韩国": true,
	"英国": true, "法国": true, "德国": true, "俄罗斯": true, "加拿大": true,
	"澳大利亚": true, "新加坡": true, "印度": true, "泰国": true, "越南": true,
	"马来西亚": true, "菲律宾": true, "印度尼西亚": true, "巴西": true, "意大利": true,
	"西班牙": true, "荷兰": true, "瑞士": true, "瑞典": true, "波兰": true,
	"china": true, "united states": true, "usa": true, "japan": true,
}

func isCountryOnly(loc string) bool {
	s := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(loc), " ", ""))
	return countryOnlyNames[s]
}

func locationScore(loc string) int {
	loc = strings.TrimSpace(loc)
	if isUnknownLocation(loc) {
		return 0
	}
	if isCountryOnly(loc) {
		return 1
	}
	hasProv := containsAny(loc, "省", "自治区", "北京", "上海", "天津", "重庆", "香港", "澳门", "台湾")
	hasCity := containsAny(loc, "市", "州", "盟", "地区")
	parts := strings.Fields(loc)
	if hasProv && hasCity {
		return 4
	}
	if len(parts) >= 3 {
		return 4
	}
	if hasProv || hasCity || len(parts) >= 2 {
		return 3
	}
	return 2
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func needsBetterLocation(loc string) bool {
	return locationScore(loc) <= 1
}

func normalizeIP(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.Trim(raw, `"'`)
	if raw == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.Trim(raw, "[]")
	ip := net.ParseIP(raw)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func isPrivateOrLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	// RFC 6598 CGNAT 100.64.0.0/10
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return true
	}
	return false
}

func peekIPLocCache(ip string) (string, bool) {
	ipLocMu.RLock()
	defer ipLocMu.RUnlock()
	ent, ok := ipLocCache[ip]
	if !ok || time.Now().After(ent.Expires) {
		return "", false
	}
	return ent.Location, true
}

func storeIPLocCache(ip, loc string, ttl time.Duration) {
	ipLocMu.Lock()
	defer ipLocMu.Unlock()
	if len(ipLocCache) > 4096 {
		now := time.Now()
		for k, v := range ipLocCache {
			if now.After(v.Expires) {
				delete(ipLocCache, k)
			}
		}
		if len(ipLocCache) > 4096 {
			ipLocCache = make(map[string]ipLocEntry, 64)
		}
	}
	ipLocCache[ip] = ipLocEntry{Location: loc, Expires: time.Now().Add(ttl)}
}

func lookupIPLocationOnline(ip string) string {
	// 并行问多家：有的源对部分 IP 只给「中国」，不能拿第一条就停。
	lookups := []func(string) string{
		lookupPconline,
		lookupBaiduIP,
		lookupCz88,
		lookupIp9,
		lookupIPAPI,
	}
	type scored struct {
		loc   string
		score int
	}
	ch := make(chan scored, len(lookups))
	for _, fn := range lookups {
		fn := fn
		go func() {
			loc := refineLocation(fn(ip))
			ch <- scored{loc: loc, score: locationScore(loc)}
		}()
	}

	best, bestScore := "", 0
	timeout := time.After(3 * time.Second)
	remaining := len(lookups)
	for remaining > 0 {
		select {
		case s := <-ch:
			remaining--
			if s.score > bestScore {
				best, bestScore = s.loc, s.score
			}
			if bestScore >= 4 {
				return best
			}
		case <-timeout:
			return best
		}
	}
	return best
}

func lookupPconline(ip string) string {
	apiURL := "https://whois.pconline.com.cn/ipJson.jsp?ip=" + url.QueryEscape(ip) + "&json=true"
	body, err := fetchIPAPI(apiURL, "")
	if err != nil {
		return ""
	}
	var result struct {
		Pro  string `json:"pro"`
		City string `json:"city"`
		Addr string `json:"addr"`
		Err  string `json:"err"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return ""
	}
	if loc := joinLocationParts(skipCountryToken(result.Pro), skipCountryToken(result.City)); loc != "" {
		return loc
	}
	if addr := stripISP(result.Addr); !isCountryOnly(addr) && addr != "" {
		return addr
	}
	return stripISP(result.Addr)
}

func lookupBaiduIP(ip string) string {
	apiURL := "https://sp0.baidu.com/8aQDcjqpAAV3otqbppnN2DJv/api.php?query=" +
		url.QueryEscape(ip) + "&resource_id=6006&ie=utf8&oe=utf8"
	body, err := fetchIPAPI(apiURL, "https://www.baidu.com/")
	if err != nil {
		return ""
	}
	var result struct {
		Status string `json:"status"`
		Data   []struct {
			Location string `json:"location"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return ""
	}
	if len(result.Data) == 0 {
		return ""
	}
	return stripISP(result.Data[0].Location)
}

func lookupCz88(ip string) string {
	apiURL := "https://www.cz88.net/api/cz88/ip/base?ip=" + url.QueryEscape(ip)
	body, err := fetchIPAPI(apiURL, "https://www.cz88.net/")
	if err != nil {
		return ""
	}
	var result struct {
		Code    int  `json:"code"`
		Success bool `json:"success"`
		Data    struct {
			Country  string `json:"country"`
			Province string `json:"province"`
			City     string `json:"city"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return ""
	}
	if result.Code != 200 && !result.Success {
		return ""
	}
	return joinLocationParts(result.Data.Country, result.Data.Province, result.Data.City)
}

func lookupIp9(ip string) string {
	apiURL := "https://ip9.com.cn/get?ip=" + url.QueryEscape(ip)
	body, err := fetchIPAPI(apiURL, "")
	if err != nil {
		return ""
	}
	var result struct {
		Ret  int `json:"ret"`
		Data struct {
			Country string `json:"country"`
			Prov    string `json:"prov"`
			City    string `json:"city"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return ""
	}
	if result.Ret != 0 && result.Ret != 200 {
		return ""
	}
	return joinLocationParts(result.Data.Country, result.Data.Prov, result.Data.City)
}

func lookupIPAPI(ip string) string {
	apiURL := fmt.Sprintf("http://ip-api.com/json/%s?lang=zh-CN&fields=status,country,regionName,city,message", url.PathEscape(ip))
	body, err := fetchIPAPI(apiURL, "")
	if err != nil {
		return ""
	}
	var result struct {
		Status     string `json:"status"`
		Country    string `json:"country"`
		RegionName string `json:"regionName"`
		City       string `json:"city"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return ""
	}
	if result.Status != "" && result.Status != "success" {
		return ""
	}
	return joinLocationParts(result.Country, result.RegionName, result.City)
}

func skipCountryToken(s string) string {
	if isCountryOnly(s) {
		return ""
	}
	return s
}

func fetchIPAPI(apiURL, referer string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Ser1oux-Blog/1.0; +https://ser1oux.cloud)")
	req.Header.Set("Accept", "application/json, text/javascript, */*;q=0.1")
	if referer != "" {
		req.Header.Set("Referer", referer)
	}
	resp, err := ipHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}
	return decodeIPAPIBody(raw, resp.Header.Get("Content-Type")), nil
}

func decodeIPAPIBody(raw []byte, contentType string) []byte {
	raw = bytes.TrimSpace(raw)
	ct := strings.ToLower(contentType)
	needGB := strings.Contains(ct, "gbk") || strings.Contains(ct, "gb2312") || strings.Contains(ct, "gb18030")
	if needGB || !utf8.Valid(raw) {
		if decoded, err := simplifiedchinese.GB18030.NewDecoder().Bytes(raw); err == nil {
			return bytes.TrimSpace(decoded)
		}
		if decoded, err := simplifiedchinese.GBK.NewDecoder().Bytes(raw); err == nil {
			return bytes.TrimSpace(decoded)
		}
	}
	return raw
}

func joinLocationParts(parts ...string) string {
	out := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, "-/")
		if p == "" || p == "0" || p == "XX" || p == "内网IP" || isUnknownLocation(p) {
			continue
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return strings.Join(out, " ")
}

func stripISP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, isp := range []string{
		"电信", "联通", "移动", "铁通", "教育网", "科技网", "广电网",
		"鹏博士", "长城宽带", "方正宽带", "阿里云", "腾讯云", "华为云",
	} {
		s = strings.TrimSpace(strings.TrimSuffix(s, isp))
	}
	return strings.TrimSpace(s)
}

func refineLocation(loc string) string {
	loc = stripISP(strings.TrimSpace(loc))
	if loc == "" || isUnknownLocation(loc) {
		return ""
	}
	parts := explodeLocationTokens(loc)
	if len(parts) > 1 && (parts[0] == "中国" || parts[0] == "中华人民共和国") {
		parts = parts[1:]
	}
	parts = prettyCNAdminNames(parts)
	return strings.Join(parts, " ")
}

func explodeLocationTokens(loc string) []string {
	fields := strings.Fields(strings.TrimSpace(loc))
	if len(fields) == 0 {
		return nil
	}
	if len(fields) >= 2 {
		return fields
	}
	compact := fields[0]
	var out []string
	if strings.HasPrefix(compact, "中国") && len([]rune(compact)) > 2 {
		out = append(out, "中国")
		compact = strings.TrimPrefix(compact, "中国")
	}
	if p, c := splitProvinceCity(compact); p != "" {
		out = append(out, p)
		if c != "" {
			out = append(out, c)
		}
		return out
	}
	if len(out) > 0 && compact != "" {
		return append(out, compact)
	}
	return fields
}

func splitProvinceCity(s string) (prov, city string) {
	for _, suf := range []string{"特别行政区", "维吾尔自治区", "壮族自治区", "回族自治区", "自治区", "省"} {
		if i := strings.Index(s, suf); i >= 0 {
			return s[:i+len(suf)], s[i+len(suf):]
		}
	}
	for _, m := range []string{"北京市", "上海市", "天津市", "重庆市"} {
		if strings.HasPrefix(s, m) {
			return m, strings.TrimPrefix(s, m)
		}
	}
	return "", ""
}

var cnProvinceNames = map[string]string{
	"北京": "北京市", "北京市": "北京市",
	"天津": "天津市", "天津市": "天津市",
	"上海": "上海市", "上海市": "上海市",
	"重庆": "重庆市", "重庆市": "重庆市",
	"河北": "河北省", "山西": "山西省", "辽宁": "辽宁省", "吉林": "吉林省", "黑龙江": "黑龙江省",
	"江苏": "江苏省", "浙江": "浙江省", "安徽": "安徽省", "福建": "福建省", "江西": "江西省", "山东": "山东省",
	"河南": "河南省", "湖北": "湖北省", "湖南": "湖南省", "广东": "广东省", "海南": "海南省",
	"四川": "四川省", "贵州": "贵州省", "云南": "云南省", "陕西": "陕西省", "甘肃": "甘肃省", "青海": "青海省",
	"台湾":  "台湾",
	"内蒙古": "内蒙古", "广西": "广西", "西藏": "西藏", "宁夏": "宁夏", "新疆": "新疆",
	"香港": "香港", "澳门": "澳门",
	"河北省": "河北省", "山西省": "山西省", "辽宁省": "辽宁省", "吉林省": "吉林省", "黑龙江省": "黑龙江省",
	"江苏省": "江苏省", "浙江省": "浙江省", "安徽省": "安徽省", "福建省": "福建省", "江西省": "江西省", "山东省": "山东省",
	"河南省": "河南省", "湖北省": "湖北省", "湖南省": "湖南省", "广东省": "广东省", "海南省": "海南省",
	"四川省": "四川省", "贵州省": "贵州省", "云南省": "云南省", "陕西省": "陕西省", "甘肃省": "甘肃省", "青海省": "青海省",
}

func prettyCNAdminNames(parts []string) []string {
	if len(parts) == 0 {
		return parts
	}
	out := append([]string(nil), parts...)
	if v, ok := cnProvinceNames[out[0]]; ok {
		out[0] = v
		if len(out) >= 2 && !hasAdminSuffix(out[1]) {
			out[1] = out[1] + "市"
		}
	}
	return out
}

func hasAdminSuffix(s string) bool {
	for _, suf := range []string{"特别行政区", "自治区", "自治州", "省", "市", "州", "盟", "县", "旗", "区"} {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	return false
}

func backfillStoredLocations() {
	time.Sleep(2 * time.Second)

	if n := backfillComments(); n > 0 {
		log.Printf("已回填 %d 条评论归属地", n)
	}
	if n := backfillMessages(); n > 0 {
		log.Printf("已回填 %d 条留言归属地", n)
	}
}

func backfillComments() int {
	changed := 0
	if err := withComments(func(store *CommentsData) error {
		for i := range store.Comments {
			if !needsBetterLocation(store.Comments[i].Location) {
				continue
			}
			ip := normalizeIP(store.Comments[i].IP)
			if ip == "" || isPrivateOrLocalIP(ip) {
				continue
			}
			loc := resolveIPLocation(ip)
			if locationScore(loc) <= locationScore(store.Comments[i].Location) {
				continue
			}
			store.Comments[i].Location = loc
			changed++
		}
		if changed == 0 {
			return errSkipSave
		}
		return nil
	}); err != nil && err != errSkipSave {
		log.Println("回填评论归属地失败:", err)
		return 0
	}
	return changed
}

func backfillMessages() int {
	changed := 0
	if err := withMessages(func(store *MessagesData) error {
		for i := range store.Messages {
			if !needsBetterLocation(store.Messages[i].Location) {
				continue
			}
			ip := normalizeIP(store.Messages[i].IP)
			if ip == "" || isPrivateOrLocalIP(ip) {
				continue
			}
			loc := resolveIPLocation(ip)
			if locationScore(loc) <= locationScore(store.Messages[i].Location) {
				continue
			}
			store.Messages[i].Location = loc
			changed++
		}
		if changed == 0 {
			return errSkipSave
		}
		return nil
	}); err != nil && err != errSkipSave {
		log.Println("回填留言归属地失败:", err)
		return 0
	}
	return changed
}
