//go:build linux

package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"flag"
	"fmt"
	"log/slog"

	bpf "github.com/aquasecurity/libbpfgo"
)

//go:embed execsnoop.bpf.o
var bpfCode []byte

type Event struct {
	PID       int32
	PPID      int32
	UID       uint32
	Retval    int32
	ArgsCount int32
	ArgsSize  uint32
	Comm      [16]byte
	// binary.Read() can't parse Args for some reason
	// Args      [7680]byte
}

func main() {
	verbose := flag.Bool("v", false, "enable libbpf debug logging")
	flag.Parse()
	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	bpf.SetLoggerCbs(bpf.Callbacks{
		Log: func(level int, msg string) {
			switch level {
			case bpf.LibbpfInfoLevel:
				slog.Info(msg)
			case bpf.LibbpfWarnLevel:
				slog.Warn(msg)
			case bpf.LibbpfDebugLevel:
				slog.Debug(msg)
			}
		},
	})

	// bpfModule, err := bpf.NewModuleFromFile("execsnoop.bpf.o")
	bpfModule, err := bpf.NewModuleFromBuffer(bpfCode, "")
	if err != nil {
		panic(err)
	}
	defer bpfModule.Close()

	if err := bpfModule.BPFLoadObject(); err != nil {
		panic(err)
	}

	enterProg, err := bpfModule.GetProgram("tracepoint__syscalls__sys_enter_execve")
	if err != nil {
		panic(err)
	}

	_, err = enterProg.AttachTracepoint("syscalls", "sys_enter_execve")
	if err != nil {
		panic(err)
	}

	exitProg, err := bpfModule.GetProgram("tracepoint__syscalls__sys_exit_execve")
	if err != nil {
		panic(err)
	}

	_, err = exitProg.AttachTracepoint("syscalls", "sys_exit_execve")
	if err != nil {
		panic(err)
	}

	eventsChan := make(chan []byte)
	lostChan := make(chan uint64)

	perfBuffer, err := bpfModule.InitPerfBuf("events", eventsChan, lostChan, 128)
	if err != nil {
		panic(err)
	}

	perfBuffer.Poll(300)
	defer perfBuffer.Close()

	for {
		select {
		case rawData := <-eventsChan:
			var event Event

			err := binary.Read(bytes.NewBuffer(rawData), binary.NativeEndian, &event)
			if err != nil {
				panic(err)
			}

			// binary.Read() gives EOF error parsing args, so read it manually from offset 40
			args := bytes.TrimRight(rawData[40:], "\x00")
			args = bytes.ReplaceAll(args, []byte{0}, []byte(" "))

			comm := bytes.TrimRight(event.Comm[:], "\x00")
			fmt.Printf("PID: %d, PPID: %d, UID: %d, Ret: %d, Comm: %s, Args: %s\n",
				event.PID, event.PPID, event.UID, event.Retval, comm, args)

		case n := <-lostChan:
			slog.Warn("events", "lost", n)
		}
	}
}
