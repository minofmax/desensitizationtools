package desensitizationtools

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"os"
	"runtime/pprof"
	"strings"
	"sync"
	"testing"
	"time"
)

func testMakeText(length int) string {
	atomCharacter := "a"
	return strings.Repeat(atomCharacter, length)
}

func TestFeatures(t *testing.T) {
	email := "{\"email\": \"caiwei@shopee.com\", \"fuzz\": \"fuzz\"}"
	maskedEmail := MaskSensitiveData(email)
	fmt.Println(maskedEmail)
	assert.Equal(t, "{\"email\": \"*****************\", \"fuzz\": \"fuzz\"}", maskedEmail.MaskedHttpPacket, "they should be equal")

	phoneNumber := "{\"phone\": \"80093324\", \"fuzz\": \"fuzz\"}"
	maskedPhoneNumber := MaskSensitiveData(phoneNumber)
	fmt.Println(maskedPhoneNumber)
	assert.Equal(t, "{\"phone\": \"11111111\", \"fuzz\": \"fuzz\"}", maskedPhoneNumber.MaskedHttpPacket, "they should be equal")

	passport := "{\"id\": \"A12345678\", \"fuzz\": \"fuzz\"}"
	maskedPassport := MaskSensitiveData(passport)
	fmt.Println(maskedPassport)
	assert.Equal(t, "{\"id\": \"*********\", \"fuzz\": \"fuzz\"}", maskedPassport.MaskedHttpPacket, "they should be equal")

	creditCard := "{\"credit\": \"5280045416637663\", \"fuzz\": \"fuzz\"}"
	maskedCreditCard := MaskSensitiveData(creditCard)
	fmt.Println(maskedCreditCard)
	assert.Equal(t, "{\"credit\": \"1111111111111111\", \"fuzz\": \"fuzz\"}", maskedCreditCard.MaskedHttpPacket, "they should be equal")

	driverLicense := "{\"driver license\": \"S1234567G\", \"fuzz\": \"fuzz\"}"
	maskedDriverLicense := MaskSensitiveData(driverLicense)
	fmt.Println(maskedDriverLicense)
	assert.Equal(t, "{\"driver license\": \"*********\", \"fuzz\": \"fuzz\"}", maskedDriverLicense.MaskedHttpPacket, "they should be equal")
}

func BenchmarkScene2(b *testing.B) {
	text1 := testMakeText(3 * 1024)
	text := testMakeText(3*1024) + strings.Repeat("{\"driver license\":\"S1234567G\", \"passport\": \"A12345678\", \"credit\": \"5280045416637663\", \"phone\": \"+6580093324\", \"email\":\"caiwei@shopee.com\",\"fuzz\": \"fuzz\"}", 2)
	flag := 0
	b.ResetTimer()

	b.Run("hyperscan", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if flag == 0 {
				MaskSensitiveData(text)
				flag = 1
			} else {
				MaskSensitiveData(text1)
				flag = 0
			}
			//MaskSensitiveData(text)
			//fmt.Println(result.HitRule)
		}
	})
}

func BenchmarkScene3(b *testing.B) {
	text := testMakeText(3*1024) + strings.Repeat("{\"driver license\":\"S1234567G\", \"passport\": \"A12345678\", \"credit\": \"5280045416637663\", \"phone\": \"+6580093324\", \"email\":\"caiwei@shopee.com\",\"fuzz\": \"fuzz\"}", 2)
	b.ResetTimer()

	b.Run("hyperscan", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			MaskSensitiveData(text)
		}
	})
}

func BenchmarkScene4(b *testing.B) {
	text := testMakeText(3*1024) + strings.Repeat("{\"credit\": \"5280045416637663\", \"fuzz\": \"fuzz\"}", 2)
	b.ResetTimer()

	b.Run("hyperscan", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			MaskSensitiveData(text)
		}
	})
}

func BenchmarkScene5(b *testing.B) {
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

func loopExecute(text string, id int) {
	startTime := time.Now().UnixMilli()
	fmt.Printf("time %d, start a goroutine %d", startTime, id)
	for {
		MaskSensitiveData(text)
		if time.Now().UnixMilli()-startTime > 360000 {
			break
		}
	}
}

func BenchmarkPprof(b *testing.B) {
	b.Run("hyperscan", func(b *testing.B) {
		f, err := os.Create("mem.pprof")
		if err != nil {
			fmt.Println(err)
			return
		}
		err = pprof.WriteHeapProfile(f)
		goRoutineNum := 3
		var wg sync.WaitGroup
		var text = testMakeText(2*1024) + "{\"credit\": \"5280045416637663\", \"fuzz\": \"fuzz\"}"
		for i := 0; i <= goRoutineNum; i++ {
			wg.Add(1)
			go func(text string, i int) {
				defer wg.Done()
				//err = pprof.StartCPUProfile(f)
				loopExecute(text, i)
			}(text, i)
		}
		wg.Wait()
		fmt.Println("execute successfully")
		if err != nil {
			return
		}
		//pprof.StopCPUProfile()
	})
}

func BenchmarkBoarderTest(b *testing.B) {
	b.Run("hyperscan", func(b *testing.B) {
		text := "{\"credit\": 5280045416637663, \"fuzz\": \"fuzz\"}"
		fmt.Println(MaskSensitiveData(text))
	})
}
