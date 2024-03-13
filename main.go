package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	dexMagic = "dex\n035\x00"
)

type memorySegment struct {
	startAddr uintptr
	endAddr   uintptr
	perms     string
	offset    int64
	devMajor  int64
	devMinor  int64
	inode     int64
	pathname  string
}

func parseMapsFile(pid int) ([]memorySegment, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var segments []memorySegment
	rd := bufio.NewReader(f)
	for {
		line, _, err := rd.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		fields := strings.Fields(string(line))
		addrs := strings.Split(fields[0], "-")

		startAddr, _ := strconv.ParseUint(addrs[0], 16, 64)
		endAddr, _ := strconv.ParseUint(addrs[1], 16, 64)
		perms := fields[1]

		offset, _ := strconv.ParseInt(fields[2], 16, 64)
		dev := strings.Split(fields[3], ":")
		devMajor, _ := strconv.ParseInt(dev[0], 16, 64)
		devMinor, _ := strconv.ParseInt(dev[1], 16, 64)

		inode, _ := strconv.ParseInt(fields[4], 10, 64)
		pathname := ""
		if len(fields) > 5 {
			pathname = fields[5]
		}

		segments = append(segments, memorySegment{
			startAddr: uintptr(startAddr),
			endAddr:   uintptr(endAddr),
			perms:     perms,
			offset:    offset,
			devMajor:  devMajor,
			devMinor:  devMinor,
			inode:     inode,
			pathname:  pathname,
		})
	}

	return segments, nil
}
func findDexInMemory(pid int, segments []memorySegment) error {
	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	memFile, err := os.Open(memPath)
	if err != nil {
		return err
	}
	defer memFile.Close()

	dexMagicLength := len(dexMagic)

	for _, s := range segments {
		if strings.Contains(s.perms, "r") {
			length := s.endAddr - s.startAddr
			data := make([]byte, length)

			_, err := memFile.Seek(int64(s.startAddr), 0)
			if err != nil {
				continue
			}

			_, err = memFile.Read(data)
			if err != nil {
				continue
			}

			offset := 0
			for offset <= len(data)-dexMagicLength {
				if string(data[offset:offset+dexMagicLength]) == dexMagic {
					if offset+36+dexMagicLength > len(data) {
						break
					}
					realSize := binary.LittleEndian.Uint32(data[offset+32 : offset+36])
					if offset+int(realSize) > len(data) {
						break
					}
					realSizeData := data[offset : offset+int(realSize)]

					f, err := os.Create(fmt.Sprintf("/data/local/tmp/%d-%x-%d.dex", pid, s.startAddr, offset))
					if err != nil {
						offset += dexMagicLength
						continue
					}
					_, err = f.Write(realSizeData)
					if err != nil {
						f.Close()
						offset += dexMagicLength
						continue
					}
					fmt.Printf("Found DEX at segment [%x-%x] and wrote to /data/local/tmp/%d-%x-%d.dex\n", s.startAddr, s.startAddr+uintptr(realSize), pid, s.startAddr, offset)
					f.Close()

					offset += int(realSize)
				} else {
					offset++
				}
			}
		}
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Please provide a PID as argument")
		os.Exit(1)
	}

	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println("Invalid PID: ", os.Args[1])
		os.Exit(1)
	}
	segments, _ := parseMapsFile(pid)
	findDexInMemory(pid, segments)
}
