package desensitizationtools

import (
	"strings"
	"sync"
)

type ScanResult struct {
	MaskedHttpPacket string `json:"maskedHttpPacket"`
	HitRule          string `json:"hitRule"`
}

var integerMatchPattern = IntegerMatchPattern

var mutex sync.Mutex
var matchDatabase = MatchDatabase()
var singleMatchDatabase = SingleMatchDatabase()

//var allInOneMatchDatabase = AllInOneMatchDatabase()
//var allInOneMatchAndReplaceDatabase = AllInOneMatchAndReplaceDatabase()
//var rulePatternMappings = RulePatternMappings

func mergeIntersectingArrays(arr [][]int) [][]int {
	if len(arr) <= 1 {
		return arr
	}

	result := [][]int{arr[0]}

	for i := 1; i < len(arr); i++ {
		current := arr[i]
		merged := false

		for j := range result {
			if result[j][1] >= current[0] {
				result[j][1] = max(result[j][1], current[1])
				merged = true
				break
			}
		}

		if !merged {
			result = append(result, current)
		}
	}

	return result
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func MaskSensitiveData(httpPacket string) ScanResult {
	mutex.Lock()
	defer mutex.Unlock()
	// identify sensitive data in httpPacket and mask
	var result ScanResult
	var hitRules []string

	//matchedPatterns, _ := allInOneMatchDatabase.FindMatchPatterns([]byte(httpPacket), nil, 10000)
	//if len(matchedPatterns) == 0 {
	//	result.MaskedHttpPacket = httpPacket
	//	result.HitRule = ""
	//	return result
	//}
	//
	//for _, id := range matchedPatterns {
	//	rule := rulePatternMappings[id]
	//	hitRules = append(hitRules, rule)
	//}
	//
	//r1 := allInOneMatchAndReplaceDatabase.FindAllStringIndex(httpPacket, 10000)
	//// 命中多个的情况，选择一个最宽的边界数组
	//r1 = mergeIntersectingArrays(r1)
	////fmt.Printf("rule: %s, matched string index boundry set: %d\n", k, r1)
	//for i := 0; i < len(r1); i++ {
	//	splits := r1[i]
	//	startPosition := splits[0]
	//	endPosition := splits[1]
	//	// 根据命中的字段分析是否为纯数字，如果为纯数字，需要将掩码改为"0"，不是则为默认的"*"
	//	sensitiveData := httpPacket[startPosition:endPosition]
	//	maskLength := endPosition - startPosition
	//	repeatAtom := "*"
	//	if integerMatchPattern.MatchString(sensitiveData) {
	//		repeatAtom = "0"
	//	}
	//	// 开始掩码
	//	maskString := strings.Repeat(repeatAtom, maskLength)
	//	httpPacket = httpPacket[:startPosition] + maskString + httpPacket[endPosition:]
	//}
	//
	//result.MaskedHttpPacket = httpPacket
	//result.HitRule = strings.Join(hitRules, ",")
	//return result
	for ruleType, database := range matchDatabase.databases {
		singleDatabase := singleMatchDatabase.databases[ruleType]
		if singleDatabase.MatchString(httpPacket) {
			hitRules = append(hitRules, ruleType)
			r1 := database.FindAllStringIndex(httpPacket, 10000)
			// 命中多个的情况，选择一个最宽的边界数组
			r1 = mergeIntersectingArrays(r1)
			for i := 0; i < len(r1); i++ {
				splits := r1[i]
				startPosition := splits[0]
				endPosition := splits[1]
				// 根据命中的字段分析是否为纯数字，如果为纯数字，需要将掩码改为"0"，不是则为默认的"*"
				sensitiveData := httpPacket[startPosition:endPosition]
				maskLength := endPosition - startPosition
				repeatAtom := "*"
				if integerMatchPattern.MatchString(sensitiveData) {
					repeatAtom = "0"
				}
				// 开始掩码
				maskString := strings.Repeat(repeatAtom, maskLength)
				httpPacket = httpPacket[:startPosition] + maskString + httpPacket[endPosition:]
			}
		}
	}
	result.MaskedHttpPacket = httpPacket
	result.HitRule = strings.Join(hitRules, ",")
	return result
}
