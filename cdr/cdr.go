package cdr

import (
	"SRGo/global"
	"fmt"
	"os"
	"strings"
)

var (
	pipe         chan map[Field]string
	fields       = getAllFields()
	stringfields = CastStringSlice(fields)
)

const CDRFilename string = "cdrs_current.txt"

func init() {
	global.WtGrp.Add(1)
	pipe = make(chan map[Field]string, global.CdrBufferSize)
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
	defer global.WtGrp.Done()
	defer file.Close()
	defer file.Sync()
	defer close(pipe)

	writeLine := func(line string) {
		if _, err := fmt.Fprintln(file, line); err != nil {
			fmt.Println("Error writing to file:", err)
		}
	}

	// write headers
	writeLine(strings.Join(stringfields, ";"))

	// write CDRs
	for fieldsmap := range pipe {
		var sb strings.Builder
		for _, f := range fields {
			sb.WriteString(fieldsmap[f])
			sb.WriteString(";")
		}
		writeLine(sb.String()[:sb.Len()-1])
	}
}
