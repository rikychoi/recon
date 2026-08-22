package service

import (
	"context"
	"encoding/xml"
	"os/exec"
	"strings"

	"github.com/rikychoi/recon/internal/model"
)

// NmapScanner는 nmap CLI를 실행하여 대상의 열린 포트를 식별하는 PortScanner 구현이다.
type NmapScanner struct {
	binary string // 실행할 바이너리 경로 (기본 "nmap")
}

// NewNmapScanner는 NmapScanner를 생성한다.
func NewNmapScanner(binary string) *NmapScanner {
	if binary == "" {
		binary = "nmap"
	}
	return &NmapScanner{binary: binary}
}

type nmapRun struct {
	XMLName xml.Name     `xml:"nmaprun"`
	Hosts   []nmapHost   `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress `xml:"address"`
	Ports     []nmapPort    `xml:"ports>port"`
}

type nmapAddress struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}

type nmapPort struct {
	PortID   int          `xml:"portid,attr"`
	Protocol string       `xml:"protocol,attr"`
	State    nmapState    `xml:"state"`
	Service  nmapService  `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name string `xml:"name,attr"`
}

// Scan은 지정한 대상 목록을 순회하며 nmap -sV -Pn -oX - 명령을 실행한다.
// nmap이 설치되어 있지 않거나 명령이 실패하면 해당 대상은 건너뛰고 빈 결과를 반환한다.
func (n *NmapScanner) Scan(ctx context.Context, targets []string) ([]model.Port, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	var ports []model.Port
	for _, target := range targets {
		cmd := exec.CommandContext(ctx, n.binary, "-Pn", "-sV", "-oX", "-", target)
		out, err := cmd.Output()
		if err != nil {
			continue
		}
		ports = append(ports, parseNmapXML(target, out)...)
	}
	return ports, nil
}

func parseNmapXML(target string, raw []byte) []model.Port {
	var run nmapRun
	if err := xml.Unmarshal(raw, &run); err != nil {
		return nil
	}

	var ports []model.Port
	for _, host := range run.Hosts {
		for _, port := range host.Ports {
			if strings.EqualFold(port.State.State, "open") {
				serviceName := port.Service.Name
				if serviceName == "" {
					serviceName = "unknown"
				}
				ports = append(ports, model.Port{
					Target:   target,
					Number:   port.PortID,
					Protocol: port.Protocol,
					State:    port.State.State,
					Service:  serviceName,
				})
			}
		}
	}
	return ports
}
