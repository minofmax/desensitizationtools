package desensitizationtools

import (
	"fmt"
	"os"
	"runtime/pprof"
	"strings"
	"sync"
	"time"
)

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
func testMakeText(length int) string {
	atomCharacter := "a"
	return strings.Repeat(atomCharacter, length)
}

func main() {
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
}
