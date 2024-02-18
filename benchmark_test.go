package desensitizationtools

import (
	"strings"
	"testing"
)

func BenchmarkLiteralMatch(b *testing.B) {
	//text1 := testMakeText(2 * 1024)
	text := testMakeText(3*1024) + strings.Repeat("{\"credit\": \"5280045416637663\", \"fuzz\": \"fuzz\"}", 50)
	//flag := 0
	b.ResetTimer()

	b.Run("hyperscan", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			//if flag == 0 {
			//	MaskSensitiveData(text)
			//	flag = 1
			//} else {
			//	MaskSensitiveData(text1)
			//	flag = 0
			//}
			MaskSensitiveData(text)
			//fmt.Println(result.HitRule)
		}
	})
}
