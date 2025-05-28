package cdr

import (
	"SRGo/global"
	"fmt"
	"os"
	"strings"
)

var (
	pipe         chan Instance
	fields       []Field  = getAllFields()
	stringfields []string = CastStringSlice(fields)
)

const CDRFilename string = "cdrs_current.txt"

func init() {
	pipe = make(chan Instance, global.CdrBufferSize)
	if file, ok := prepareCdrFiles(); ok {
		go writeCDRs(file)
	}
}

func prepareCdrFiles() (*os.File, bool) {
	if info, err := os.Stat(CDRFilename); err == nil {
		modtm := info.ModTime().UTC().Format(global.DicTFs[global.CDRTimestamp])
		err = os.Rename(CDRFilename, strings.Replace(CDRFilename, "current", modtm, 1))
		if err != nil {
			global.LogError(global.LTSystem, fmt.Sprint("Error renaming existing CDR file:", err))
			return nil, false
		}
	}

	file, err := os.OpenFile(CDRFilename, os.O_CREATE|os.O_WRONLY, 0644) // os.O_APPEND|
	if err != nil {
		global.LogWarning(global.LTSystem, fmt.Sprint("Error opening CDR file:", err))
		return nil, false
	}

	return file, true
}

func writeCDRs(file *os.File) {
	defer file.Close()
	defer close(pipe)

	writeLine := func(line string) {
		if _, err := fmt.Fprintln(file, line); err != nil {
			fmt.Println("Error writing to file:", err)
		}
	}

	// write headers
	writeLine(strings.Join(stringfields, ";"))

	// write CDRs
	for inst := range pipe {
		var sb strings.Builder
		for _, f := range fields {
			sb.WriteString(inst.data[f])
			sb.WriteString(";")
		}
		writeLine(sb.String()[:sb.Len()-1])
	}
}
