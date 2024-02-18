# Desensitization Tool

## Background

1. Mainly for desensitized storage of some sensitive data.
2. Mainly for figure out sensitive api from traffic

## Features

1. Identify sensitive data
2. Mask sensitive data
3. Categorize sensitive data

## Using

```go
package main

import (
	"fmt"
	"github.com/minofmax/desensitizationtools"
)

func main() {
	var a = "123"
	var result = desensitization.MaskSensitiveData(a)
	fmt.Println(result.HitRule, result.MaskedHttpPacket)
}

```

## TIPS

1. Building hyperscan databases when compile the project, so there exist data consistency problem.
2. Using mutex lock in MakeSensitiveData method to avoid the data consistency problem.