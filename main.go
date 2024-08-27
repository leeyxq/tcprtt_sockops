//go:build linux

// This program demonstrates attaching an eBPF program to
// a cgroupv2 path and using sockops to process TCP socket events.
// It prints the IPs/ports/RTT information every time TCP sockets
// update their internal RTT value.
// It supports only IPv4 for this example.
//
// Sample output:
//
// examples# go run -exec sudo ./tcprtt_sockops
// 2022/08/14 20:58:03 eBPF program loaded and attached on cgroup /sys/fs/cgroup/unified
// 2022/08/14 20:58:03 Src addr        Port   -> Dest addr       Port   RTT (ms)
// 2022/08/14 20:58:09 10.0.1.205      54844  -> 20.42.73.25     443    67
// 2022/08/14 20:58:09 10.0.1.205      54844  -> 20.42.73.25     443    67
// 2022/08/14 20:58:33 10.0.1.205      38620  -> 140.82.121.4    443    26
// 2022/08/14 20:58:33 10.0.1.205      38620  -> 140.82.121.4    443    26
// 2022/08/14 20:58:43 34.67.40.146    45380  -> 10.0.1.205      5201   106
// 2022/08/14 20:58:43 34.67.40.146    45380  -> 10.0.1.205      5201   106

package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/pouriyajamshidi/sockops/btfs"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go tcprtt ./bpf/tcprtt_sockops.c -type rtt_event - clang-14 -O2 -g -Wall -Werror -Wno-address-of-packed-member -- -I ./bpf/vmlinux.h

type rttEvent struct {
	Sport uint16
	Dport uint16
	Saddr uint32
	Daddr uint32
	Srtt  uint32
}

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Find the path to a cgroup enabled to version 2
	cgroupPath, err := findCgroupPath()
	if err != nil {
		log.Fatal(err)
	}

	var btfSpec *btf.Spec

	btfSpec, err = btf.LoadKernelSpec()
	if err != nil {
		btfFileName := "3.10.0-957.el7.x86_64.btf"
		btfFileReader, err := btfs.BtfFiles.ReadFile(btfFileName)
		if err != nil {
			log.Fatalf("reading %v BTF file %v", btfFileReader, err)
		}

		log.Printf("Opened %s\n", btfFileName)

		btfSpec, err = btf.LoadSpecFromReader(bytes.NewReader(btfFileReader))
		if err != nil {
			log.Fatalf("creating BTF handle: %v", err)
		}
		log.Println("Created BTF handle")
	} else {
		log.Println("Kernel is shiped with BTF")
	}

	objs := tcprttObjects{}
	if err := loadTcprttObjects(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			KernelTypes: btfSpec,
		},
	}); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Attach ebpf program to a cgroupv2
	link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: objs.tcprttPrograms.BpfSockopsCb,
		Attach:  ebpf.AttachCGroupSockOps,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer link.Close()

	log.Printf("eBPF program loaded and attached on cgroup %s\n", cgroupPath)

	rd, err := ringbuf.NewReader(objs.tcprttMaps.RttEvents)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	log.Printf("%-15s %-6s -> %-15s %-6s %-6s",
		"Src addr",
		"Port",
		"Dest addr",
		"Port",
		"RTT (ms)",
	)
	go readLoop(rd)

	// Wait
	<-stopper
}

func findCgroupPath() (string, error) {
	cgroupPath := "/sys/fs/cgroup"

	var st syscall.Statfs_t
	err := syscall.Statfs(cgroupPath, &st)
	if err != nil {
		return "", err
	}
	isCgroupV2Enabled := st.Type == unix.CGROUP2_SUPER_MAGIC
	if !isCgroupV2Enabled {
		cgroupPath = filepath.Join(cgroupPath, "unified")
	}
	return cgroupPath, nil
}

func readLoop(rd *ringbuf.Reader) {
	var event rttEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		// Parse the ringbuf event entry into a bpfRttEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		log.Printf("%-15s %-6d -> %-15s %-6d %-6d",
			intToIP(event.Saddr),
			event.Sport,
			intToIP(event.Daddr),
			event.Dport,
			event.Srtt,
		)
	}
}

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}
