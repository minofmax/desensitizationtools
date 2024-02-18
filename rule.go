package desensitizationtools

import "github.com/flier/gohs/hyperscan"

var rules = map[string][]string{
	"email": {
		"\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]+\\b",
	},
	"phone number": {
		"\\b(?:00|\\+65)?-?[689]\\d{7}\\b",
		"\\b(?:00|\\+62)?-?0?8\\d{8,14}\\b",
		"\\b(?:00|\\+63)?-?0?9\\d{8}\\b",
		"\\b(?:00|\\+60)?-?01\\d{8}\\b",
		"\\b(?:00|\\+66)?-?(08|09|06)\\d{8}\\b",
		//"\\b(?:00|\\+84)?-?1\\d{8}\\b",     // delete
		//"\\b(?:00|\\+55)?-?[1-9]\\d{8}\\b", //delete
		"\\b(?:\\b09(?:\\d\\d\\d-\\d{5}|\\d\\d-\\d\\d\\d-\\d\\d)\\b)",
		"\\b(?:\\b\\+886\\d{9}\\b)",
		//"(?:\\b(?:\\(?(?:02|03|037|039|04|049|05|06|07|08|089)\\)?-?)?\\d{4}-?\\d{4}\\b)",
	},
	"id card": {
		"\\b[SFTG]\\d{7}[JZIHGFEDCBAXWUTRQPNMLK]\\b",
		"\\b\\d{2}\\.?\\d{4}\\.?(0[1-9]|[12][0-9]|3[01])(0[1-9]|1[0-2])(\\d{2})\\.?\\d{4}\\b",
		"\\b\\d{2}(?:0\\d|1[012])\\d{9}\\b",
		"\\b[a-z][12]\\d{8}\\b",
		"\\b(?:19|20)\\d{2}-?\\d{2}-?\\d{3}[1-2]\\b",
		"\\b[1-8]-?[0-9]{4}-?[0-9]{5}-?[0-9]{2}-?[0-9]\\b",
		"\\b[0-9]{8}(?:0[1-9]|1[0-9]|2[0-8])[0-9]{2}\\b",
	},
	"debit card": {
		"\\b5[1-5]\\d{2}[- ]\\d{4}[- ]\\d{4}[- ]\\d{4}\\b",
		"\\b5[1-5]\\d{14}\\b",
		"\\b2[2-7]\\d{2}[- ]\\d{4}[- ]\\d{4}[- ]\\d{4}\\b",
		"\\b2[2-7]\\d{14}\\b",
		"\\b4\\d{3}[- ]\\d{4}[- ]\\d{4}[- ]\\d{4}\\b",
		"\\b4\\d{15}\\b",
		"\\b622\\d{13,16}\\b",
		"\\b(?:603601|603265|621977|603708|602969|601428|603367|603694)\\d{10}\\b",
	},
	"passport": {
		"\\bS\\d{7}[a-zA-Z]\\b",
		"\\bIDN[123]\\d{5}\\b",
		"\\b[a-zA-Z]([a-zA-Z]?\\d{6}|[a-zA-Z]\\d{7}|\\d{7}[a-zA-Z])\\b",
		"\\b3\\d{8}\\b",
		"\\b[AHKahk]\\d{8}\\b",
		"\\bTH[PDS][a-zA-Z0-9]{6}\\b",
		"\\bVNM[PDS][0-9]{5}\\b",
		"\\bBR[PDS][0-9]{6}\\b",
	},
	"driver licence": {
		"\\b[SF]\\d{7}[a-zA-Z]\\b",
		"\\bMY[ABDEFG][0-9a-zA-Z]{8}[a-zA-Z]\\b",
		"\\bTH[56789]\\d{7}\\b",
		"\\bVN\\d{9}[a-zA-Z]\\b",
	},
}

type MatchedDatabases struct {
	databases map[string]hyperscan.BlockDatabase
	//mutex     sync.Mutex
}

var IntegerMatchPattern, _ = hyperscan.NewBlockDatabase(hyperscan.NewPattern("^\\d+$", hyperscan.SingleMatch))

//var RulePatternMappings = make(map[int]string)

//var AllInOneMatchDatabase = func() hyperscan.BlockDatabase {
//	i := 0
//	var Patterns []*hyperscan.Pattern
//	for _, v := range rules {
//		for _, rule := range v {
//			p := hyperscan.NewPattern(rule, hyperscan.SingleMatch)
//			p.Id = i
//			Patterns = append(Patterns, p)
//			i += 1
//		}
//	}
//	database, _ := hyperscan.NewBlockDatabase(Patterns...)
//	return database
//}
//
//var AllInOneMatchAndReplaceDatabase = func() hyperscan.BlockDatabase {
//	i := 0
//	var Patterns []*hyperscan.Pattern
//	for k, v := range rules {
//		for _, rule := range v {
//			p := hyperscan.NewPattern(rule, hyperscan.SomLeftMost)
//			p.Id = i
//			Patterns = append(Patterns, p)
//			RulePatternMappings[i] = k
//			i += 1
//		}
//	}
//	database, _ := hyperscan.NewBlockDatabase(Patterns...)
//	return database
//}

var MatchDatabase = func() MatchedDatabases {
	var matchedDatabase MatchedDatabases
	var matchDatabases = map[string]hyperscan.BlockDatabase{}
	for k, v := range rules {
		var Patterns []*hyperscan.Pattern
		for _, rule := range v {
			p := hyperscan.NewPattern(rule, hyperscan.SomLeftMost)
			Patterns = append(Patterns, p)
		}
		database, err := hyperscan.NewBlockDatabase(Patterns...)
		matchDatabases[k] = database
		if err != nil {
			continue
		}
	}
	matchedDatabase.databases = matchDatabases
	//return matchDatabases
	return matchedDatabase
}

var SingleMatchDatabase = func() MatchedDatabases {
	var databases MatchedDatabases
	var matchDatabases = map[string]hyperscan.BlockDatabase{}
	for k, v := range rules {
		var Patterns []*hyperscan.Pattern
		i := 0
		for _, rule := range v {
			p := hyperscan.NewPattern(rule, hyperscan.SingleMatch)
			p.Id = i
			Patterns = append(Patterns, p)
			i += 1
		}
		database, err1 := hyperscan.NewBlockDatabase(Patterns...)
		matchDatabases[k] = database
		if err1 != nil {
			continue
		}
	}
	databases.databases = matchDatabases
	return databases
}
