//go:build linux
// +build linux

package ebpf

import (
	"context"
	"encoding/binary"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
	"github.com/hashicorp/consul-server-connection-manager/discovery"
	"math"
	"net"
	"os"
	"path"
	"strings"
	"time"
)

//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf cgroup_connect4.c -- -I./headers

const bpfFSPath = " /consul-ebf/fs/bpf"
const sysGroupFSPath = "/consul-ebf/fs/cgroup"

type BpfProgram struct {
	objs       bpfObjects
	logger     logr.Logger
	l          link.Link
	ch         chan string
	discoverer discovery.Discoverer
	serversMap map[string]int
	cancel     context.CancelFunc
	serverKeys map[string][]uint32
}

func New(logger logr.Logger, discoverer discovery.Discoverer) (*BpfProgram, error) {
	serversMap := make(map[string]int)

	bpfProgram := BpfProgram{logger: logger, discoverer: discoverer, serversMap: serversMap}
	bpfProgram.ch = make(chan string)
	bpfProgram.serverKeys = make(map[string][]uint32, 0)
	err := bpfProgram.initServers()
	if err != nil {
		logger.Error(err, "init servers failed")
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	go bpfProgram.run(ctx)
	bpfProgram.cancel = cancel
	return &bpfProgram, nil

}

func (p *BpfProgram) LoadBpfProgram() error {
	// Name of the kernel function we're tracing
	fn := "consul_bpf"
	//if err := rlimit.RemoveMemlock(); err != nil {
	//	p.logger.Error(err, "memlock error")
	//	return err
	//}
	pinPath := path.Join(bpfFSPath, fn)
	if err := os.MkdirAll(pinPath, 0777); err != nil {
		p.logger.Error(err, "failed to create bpf fs subpath", "path", pinPath)
		return err
	}

	// Load pre-compiled programs and maps into the kernel.
	p.objs = bpfObjects{}
	if err := loadBpfObjects(&p.objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			// Pin the map to the BPF filesystem and configure the
			// library to automatically re-write it in the BPF
			// program so it can be re-used if it already exists or
			// create it if not
			PinPath: pinPath,
		},
	}); err != nil {
		p.logger.Error(err, "loading objects")
		return err
	}
	info, err := p.objs.bpfMaps.V4SvcMap.Info()
	if err != nil {
		p.logger.Error(err, "Cannot get map info")
		return err
	}
	p.logger.Info("eBPF Program successfully loaded ", "info", info)

	// Link the proxy program to the default cgroup.
	p.l, err = link.AttachCgroup(link.CgroupOptions{
		Path:    sysGroupFSPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: p.objs.Sock4Connect,
	})
	if err != nil {
		p.logger.Error(err, "Attach failed")
		return err
	}

	p.logger.Info("eBPF Attach successfully loaded ", "info", info)

	return nil
}

func (p *BpfProgram) run(ctx context.Context) {

	tick := time.NewTicker(5 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			p.logger.Info("Time to rebalance servers")
			err := p.reconcile()
			if err != nil {
				p.logger.Error(err, "not able to reconcile")
			}
		case ip := <-p.ch:
			err := p.inject(ip)
			if err != nil {
				p.logger.Error(err, "not able to inject IP")
			}
		}

	}
}

func (p *BpfProgram) Inject(ip string) {
	p.logger.Info("injecting IP")
	p.ch <- ip
}

func (p *BpfProgram) UnloadBpfProgram() error {
	p.logger.Info("Cleaning up eBPF program")
	err := p.objs.Close()
	if err != nil {
		return err
	}
	p.cancel()
	return p.l.Close()
}

func (p *BpfProgram) getServer() string {
	minV := math.MaxInt
	minK := ""
	for k, v := range p.serverKeys {
		if minV > len(v) {
			minV = len(v)
			minK = k
		}
	}
	return minK
}

func (p *BpfProgram) initServers() error {
	addrs, err := p.discoverer.Discover(context.Background())
	if err != nil {
		return err
	}

	for _, a := range addrs {
		ip := strings.SplitN(a.String(), ":", 2)[0]
		p.serversMap[ip] = 0
	}
	return nil
}

func ipToInt(ip string) uint32 {
	return binary.LittleEndian.Uint32(net.ParseIP(ip).To4())
}

func (p *BpfProgram) inject(ip string) error {

	serverIP := p.getServer()
	defer func() {
		p.serversMap[serverIP]++
	}()

	p.logger.Info("Loading with", "key addr", ip,
		"server addr", serverIP)

	fakeServiceKey := ipToInt(ip)

	fakeBackendIP := ipToInt(serverIP)

	p.logger.Info("Loading with (int)", "key addr", fakeBackendIP,
		"server addr", fakeServiceKey)

	if err := p.objs.V4SvcMap.Update(fakeServiceKey, bpfConsulServers{fakeBackendIP}, ebpf.UpdateAny); err != nil {
		p.logger.Error(err, "Failed Loading a fake service")
		return err
	}
	if _, ok := p.serverKeys[serverIP]; !ok {
		p.serverKeys[serverIP] = make([]uint32, 0)
	}
	p.serverKeys[serverIP] = append(p.serverKeys[serverIP], fakeServiceKey)

	return nil
}

func findAddrs(addr []discovery.Addr, ip string) bool {
	for _, a := range addr {
		if a.IP.String() == ip {
			return true
		}
	}
	return false
}

func (p *BpfProgram) reconcile() error {
	addrs, err := p.discoverer.Discover(context.Background())
	p.logger.Info("got following servers", "servers", addrs, "keys", p.serverKeys)
	if err != nil {
		return err
	}

	//add missing servers
	for _, a := range addrs {
		if _, ok := p.serverKeys[a.IP.String()]; !ok {
			p.serverKeys[a.IP.String()] = make([]uint32, 0)
			p.logger.Info("got new server1", "server", a.IP.String())
		}
	}

	// remove old servers
	for k, keys := range p.serverKeys {
		if !findAddrs(addrs, k) {
			delete(p.serverKeys, k)
			newserver := p.getServer()
			p.logger.Info("transferring vips", "oldserver", k, "newserver", newserver)
			for _, vip := range keys {
				if err := p.objs.V4SvcMap.Update(vip, bpfConsulServers{ipToInt(newserver)}, ebpf.UpdateAny); err != nil {
					p.logger.Error(err, "Failed Loading a vip")
					return err
				}
			}
			p.serverKeys[newserver] = append(p.serverKeys[newserver], keys...)
			p.logger.Info("transferring success", "oldserver", k, "newserver", newserver)
		}
	}

	return nil
}
