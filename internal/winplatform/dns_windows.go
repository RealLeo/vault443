package winplatform

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"vault443/internal/securefs"
)

type DNSPlan struct {
	Domains         []string
	Servers         []netip.Addr
	Interface       winipcfg.LUID
	Active, Default bool
	Priority        int
}
type dnsBackup struct {
	GUID       windows.GUID `json:"guid"`
	IPv6       bool         `json:"ipv6"`
	NameServer string       `json:"nameServer"`
}
type dnsState struct {
	Backups  map[string]dnsBackup    `json:"backups"`
	Fallback []netip.Addr            `json:"fallback"`
	ByGUID   map[string][]netip.Addr `json:"fallbackByGuid,omitempty"`
	NRPT     *nrptState              `json:"nrpt,omitempty"`
}
type DNS struct {
	mu              sync.Mutex
	plans           map[string]DNSPlan
	saved           map[string]dnsBackup
	fallback        []netip.Addr
	byGUID          map[string][]netip.Addr
	physical        winipcfg.LUID
	path            string
	started         bool
	fallbackAllowed func() bool
	nrpt            *nrptState
	nrptReady       bool
	nrptKey         string
	nrptConflict    *nrptConflictError
	blocked         map[string]bool
	blockAll        bool
	nrptRun         nrptRunner
}

func NewDNS(dir string) (*DNS, error) {
	d := &DNS{path: filepath.Join(dir, "windows-dns.json"), plans: map[string]DNSPlan{}, saved: map[string]dnsBackup{}, byGUID: map[string][]netip.Addr{}, blocked: map[string]bool{}}
	data, err := os.ReadFile(d.path)
	if err == nil {
		var state dnsState
		if len(data) > 1<<20 || json.Unmarshal(data, &state) != nil || state.Backups == nil {
			return nil, errors.New("invalid private Windows DNS backup")
		}
		d.saved, d.fallback = state.Backups, state.Fallback
		if err = validateNRPTState(state.NRPT); err != nil {
			return nil, err
		}
		d.nrpt = state.NRPT
		if state.ByGUID != nil {
			d.byGUID = state.ByGUID
		} else {
			for _, backup := range d.saved {
				d.byGUID[backup.GUID.String()] = append([]netip.Addr(nil), state.Fallback...)
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return d, nil
}
func (d *DNS) Start(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.started {
		if len(d.plans) > 0 {
			return d.activatePlansLocked(ctx)
		}
		return nil
	}
	var packets []net.PacketConn
	var streams []net.Listener
	for _, address := range []string{"127.0.0.1:53", "[::1]:53"} {
		packet, err := net.ListenPacket("udp", address)
		if err != nil {
			for _, p := range packets {
				p.Close()
			}
			for _, s := range streams {
				s.Close()
			}
			return errors.New("cannot reserve local DNS port 53")
		}
		packets = append(packets, packet)
		stream, err := net.Listen("tcp", address)
		if err != nil {
			for _, p := range packets {
				p.Close()
			}
			for _, s := range streams {
				s.Close()
			}
			return errors.New("cannot reserve local DNS port 53")
		}
		streams = append(streams, stream)
	}
	slots := make(chan struct{}, 256)
	for _, packet := range packets {
		go func(p net.PacketConn) {
			buf := make([]byte, 65535)
			for {
				n, addr, err := p.ReadFrom(buf)
				if err != nil {
					return
				}
				query := append([]byte(nil), buf[:n]...)
				select {
				case slots <- struct{}{}:
					go func() {
						defer func() { <-slots }()
						answer := d.query(ctx, query, false)
						if answer != nil {
							p.WriteTo(answer, addr)
						}
					}()
				default:
				}
			}
		}(packet)
	}
	for _, stream := range streams {
		go func(s net.Listener) {
			for {
				conn, err := s.Accept()
				if err != nil {
					return
				}
				select {
				case slots <- struct{}{}:
					go func() {
						defer func() { <-slots }()
						defer conn.Close()
						for {
							conn.SetDeadline(time.Now().Add(10 * time.Second))
							var size [2]byte
							if _, e := io.ReadFull(conn, size[:]); e != nil {
								return
							}
							n := binary.BigEndian.Uint16(size[:])
							if n < 12 {
								return
							}
							query := make([]byte, n)
							if _, e := io.ReadFull(conn, query); e != nil {
								return
							}
							answer := d.query(ctx, query, true)
							if answer == nil {
								return
							}
							binary.BigEndian.PutUint16(size[:], uint16(len(answer)))
							if _, e := conn.Write(append(size[:], answer...)); e != nil {
								return
							}
						}
					}()
				default:
					conn.Close()
				}
			}
		}(stream)
	}
	go func() {
		<-ctx.Done()
		for _, p := range packets {
			p.Close()
		}
		for _, s := range streams {
			s.Close()
		}
	}()
	d.started = true
	// Listener reservation precedes any newly installed DNS policy. Startup
	// recovery may have collected inactive work plans before this call.
	if len(d.plans) > 0 {
		return d.activatePlansLocked(ctx)
	}
	return nil
}
func staticDNS(guid windows.GUID, v6 bool) (string, error) {
	family := "Tcpip"
	if v6 {
		family = "Tcpip6"
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+family+`\Parameters\Interfaces\`+guid.String(), registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer key.Close()
	value, _, err := key.GetStringValue("NameServer")
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	return value, err
}
func setStaticDNS(backup dnsBackup, value string) error {
	text, err := windows.UTF16PtrFromString(value)
	if err != nil {
		return err
	}
	settings := &winipcfg.DnsInterfaceSettings{Version: winipcfg.DnsInterfaceSettingsVersion1, Flags: winipcfg.DnsInterfaceSettingsFlagNameserver, NameServer: text}
	if backup.IPv6 {
		settings.Flags |= winipcfg.DnsInterfaceSettingsFlagIPv6
	}
	return winipcfg.SetInterfaceDnsSettings(backup.GUID, settings)
}
func (d *DNS) provision(luid winipcfg.LUID) error {
	guid, err := luid.GUID()
	if err != nil {
		return err
	}
	// DHCP renewals can replace DNS servers without changing the adapter LUID.
	servers, e := d.underlayServersLocked(luid, guid.String())
	if e != nil {
		return e
	}
	d.fallback = servers
	d.physical = luid
	// NRPT selects the existing loopback coordinator without binding DNSClient
	// TCP sockets to a physical adapter. New plans never modify adapter DNS.
	return nil
}
func validUnderlayDNS(ip netip.Addr, v6 bool) bool {
	return ip.IsValid() && !ip.Is4In6() && ip.Is6() == v6 && !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsMulticast()
}

// Static NameServer overrides DHCP. Read-only dynamic registry formats also
// match upstream OpenVPN's GetItfDnsServersV4/V6 implementation:
// https://github.com/OpenVPN/openvpn/blob/master/src/openvpnserv/interactive.c
// Microsoft documents NameServer/DhcpNameServer precedence at:
// https://learn.microsoft.com/troubleshoot/windows-client/networking/tcpip-and-nbt-configuration-parameters
func dynamicDNS(guid windows.GUID, v6 bool) ([]netip.Addr, bool, error) {
	family, value := "Tcpip", "DhcpNameServer"
	if v6 {
		family, value = "Tcpip6", "Dhcpv6DNSServers"
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+family+`\Parameters\Interfaces\`+guid.String(), registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer key.Close()
	enabled, _, enabledErr := key.GetIntegerValue("EnableDHCP")
	if enabledErr != nil && !errors.Is(enabledErr, registry.ErrNotExist) {
		return nil, false, enabledErr
	}
	if enabledErr == nil && enabled == 0 {
		return nil, false, nil
	}
	if !v6 {
		text, _, err := key.GetStringValue(value)
		if errors.Is(err, registry.ErrNotExist) {
			return nil, false, nil
		}
		return parseUnderlayDNS(text, false), err == nil, err
	}
	data, _, err := key.GetBinaryValue(value)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if len(data)%16 != 0 || len(data) > 4096 {
		return nil, false, errors.New("invalid DHCPv6 DNS address list")
	}
	var result []netip.Addr
	for len(data) > 0 {
		ip := netip.AddrFrom16([16]byte(data[:16]))
		if validUnderlayDNS(ip, true) {
			result = append(result, ip)
		}
		data = data[16:]
	}
	return result, true, nil
}
func parseUnderlayDNS(text string, v6 bool) []netip.Addr {
	var result []netip.Addr
	for _, raw := range strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' }) {
		if ip, err := netip.ParseAddr(raw); err == nil && validUnderlayDNS(ip, v6) {
			result = append(result, ip)
		}
	}
	return result
}
func selectUnderlayDNS(static string, dynamic []netip.Addr, dynamicPresent bool, initial []netip.Addr, v6 bool) []netip.Addr {
	if strings.TrimSpace(static) != "" {
		return parseUnderlayDNS(static, v6)
	}
	if dynamicPresent {
		return append([]netip.Addr(nil), dynamic...)
	}
	var result []netip.Addr
	for _, ip := range initial {
		if validUnderlayDNS(ip, v6) {
			result = append(result, ip)
		}
	}
	return result
}
func (d *DNS) underlayServersLocked(luid winipcfg.LUID, id string) ([]netip.Addr, error) {
	guid, err := windows.GUIDFromString(id)
	if err != nil {
		return nil, err
	}
	live, err := luid.DNS()
	if err != nil {
		return nil, err
	}
	var result []netip.Addr
	for _, v6 := range []bool{false, true} {
		key := id
		if v6 {
			key += "/6"
		}
		backup, saved := d.saved[key]
		if !saved {
			// Always refresh from the IP Helper view when no legacy override
			// remains, including DHCP renewals and IPv6 RDNSS changes.
			result = append(result, selectUnderlayDNS("", nil, false, live, v6)...)
			continue
		}
		static := backup.NameServer
		if strings.TrimSpace(static) != "" {
			result = append(result, selectUnderlayDNS(static, nil, false, nil, v6)...)
			continue
		}
		dynamic, present, err := dynamicDNS(guid, v6)
		if err != nil {
			return nil, err
		}
		result = append(result, selectUnderlayDNS(static, dynamic, present, d.byGUID[id], v6)...)
	}
	if !reflect.DeepEqual(d.byGUID[id], result) {
		previous, hadPrevious := d.byGUID[id]
		previousFallback := d.fallback
		d.byGUID[id] = append([]netip.Addr(nil), result...)
		if d.physical == luid {
			d.fallback = append([]netip.Addr(nil), result...)
		}
		if err = d.saveLocked(); err != nil {
			if hadPrevious {
				d.byGUID[id] = previous
			} else {
				delete(d.byGUID, id)
			}
			d.fallback = previousFallback
			return nil, err
		}
	}
	return result, nil
}
func (d *DNS) UnderlayServers(luid winipcfg.LUID) ([]netip.Addr, error) {
	guid, err := luid.GUID()
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.underlayServersLocked(luid, guid.String())
}
func (d *DNS) Set(id string, plan DNSPlan, uplink winipcfg.LUID) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	next := copyDNSPlans(d.plans)
	next[id] = plan
	return d.replacePlansLocked(next, uplink)
}

// SetGroup replaces one coordinator's plans atomically. Other VPN plans retain
// their precedence and no request can fall through a partially updated group.
func (d *DNS) SetGroup(prefix string, plans map[string]DNSPlan, uplink winipcfg.LUID) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if prefix == "" {
		return errors.New("invalid DNS plan owner")
	}
	for key := range plans {
		if !strings.HasPrefix(key, prefix) {
			return errors.New("invalid DNS plan owner")
		}
	}
	next := copyDNSPlans(d.plans)
	for key := range next {
		if strings.HasPrefix(key, prefix) {
			delete(next, key)
		}
	}
	for key, plan := range plans {
		next[key] = plan
	}
	return d.replacePlansLocked(next, uplink)
}
func (d *DNS) Remove(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.plans, id)
	delete(d.blocked, id)
	if len(d.plans) == 0 {
		return d.restore()
	}
	if d.started {
		return d.activatePlansLocked(context.Background())
	}
	return nil
}
func (d *DNS) Restore() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.plans = map[string]DNSPlan{}
	d.blocked = map[string]bool{}
	return d.restore()
}
func (d *DNS) saveLocked() error {
	data, err := json.Marshal(dnsState{Backups: d.saved, Fallback: d.fallback, ByGUID: d.byGUID, NRPT: d.nrpt})
	if err != nil {
		return err
	}
	return securefs.Write(d.path, data)
}

// Migration keeps all desired plans and the owned NRPT identity intact. Each
// original adapter setting is durably removed from the journal separately.
func (d *DNS) restoreLegacyLocked() error {
	for key, backup := range d.saved {
		current, err := staticDNS(backup.GUID, backup.IPv6)
		if err != nil {
			return err
		}
		expected := "127.0.0.1"
		if backup.IPv6 {
			expected = "::1"
		}
		if current != backup.NameServer && strings.TrimSpace(current) != expected {
			return errors.New("legacy adapter DNS changed independently; recovery identity retained")
		}
		if err := setStaticDNS(backup, backup.NameServer); err != nil {
			// Disappeared USB/network adapters cannot be configured. Retain their
			// backup so a later maintenance run can finish the restoration.
			return err
		}
		delete(d.saved, key)
		if err := d.saveLocked(); err != nil {
			d.saved[key] = backup
			return err
		}
	}
	return nil
}
func (d *DNS) restore() error {
	d.blockAll = true
	// Explicit release restores legacy settings even when there is no active
	// policy to migrate; it must not install a new catch-all during uninstall.
	if err := d.restoreLegacyLocked(); err != nil {
		return err
	}
	if err := d.removeNRPTLocked(context.Background()); err != nil {
		return err
	}
	d.physical = 0
	d.fallback = nil
	d.byGUID = map[string][]netip.Addr{}
	previous := d.nrpt
	d.nrpt = nil
	if err := d.saveLocked(); err != nil {
		d.nrpt = previous
		return err
	}
	d.nrptReady, d.blockAll = false, false
	d.nrptKey, d.nrptConflict = "", nil
	return nil
}
func dnsQuestion(query []byte) (dnsmessage.Header, dnsmessage.Question, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil || header.Response || header.OpCode != 0 {
		return header, dnsmessage.Question{}, errors.New("invalid DNS query")
	}
	question, err := parser.Question()
	if err != nil {
		return header, question, err
	}
	if _, e := parser.Question(); e != dnsmessage.ErrSectionDone {
		return header, question, errors.New("exactly one DNS question is required")
	}
	return header, question, nil
}
func dnsFailure(header dnsmessage.Header, question dnsmessage.Question) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true, RecursionDesired: header.RecursionDesired, RecursionAvailable: true, RCode: dnsmessage.RCodeServerFailure})
	b.StartQuestions()
	if b.Question(question) != nil {
		return nil
	}
	answer, _ := b.Finish()
	return answer
}
func (d *DNS) query(parent context.Context, query []byte, tcp bool) []byte {
	header, question, err := dnsQuestion(query)
	if err != nil {
		return nil
	}
	name := strings.ToLower(strings.TrimSuffix(question.Name.String(), "."))
	d.mu.Lock()
	if d.blockAll || (len(d.plans) > 0 && (!d.started || !d.nrptReady)) {
		d.mu.Unlock()
		return dnsFailure(header, question)
	}
	var plan DNSPlan
	matched := -1
	keys := make([]string, 0, len(d.plans))
	for key := range d.plans {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		candidate := d.plans[key]
		for _, domain := range candidate.Domains {
			domain = strings.ToLower(strings.Trim(domain, "."))
			if name == domain || strings.HasSuffix(name, "."+domain) {
				if len(domain) > matched {
					plan = candidate
					if d.blocked[key] {
						plan.Active = false
					}
					matched = len(domain)
				}
			}
		}
	}
	if matched < 0 {
		priority := -1
		for _, key := range keys {
			candidate := d.plans[key]
			if candidate.Default && candidate.Priority > priority {
				plan = candidate
				if d.blocked[key] {
					plan.Active = false
				}
				priority = candidate.Priority
			}
		}
		if priority < 0 {
			plan = DNSPlan{Servers: append([]netip.Addr(nil), d.fallback...), Interface: d.physical, Active: true}
			if d.fallbackAllowed != nil && !d.fallbackAllowed() {
				plan.Active = false
			}
		}
	}
	d.mu.Unlock()
	if !plan.Active || plan.Interface == 0 {
		return dnsFailure(header, question)
	}
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	for _, server := range plan.Servers {
		answer, e := exchangeDNS(ctx, query, server, plan.Interface, tcp)
		if e != nil {
			continue
		}
		var parser dnsmessage.Parser
		reply, e := parser.Start(answer)
		if e != nil || !reply.Response || reply.ID != header.ID {
			continue
		}
		q, e := parser.Question()
		if e != nil || q != question {
			continue
		}
		if reply.Truncated && !tcp {
			answer, e = exchangeDNS(ctx, query, server, plan.Interface, true)
			if e != nil {
				continue
			}
		}
		return answer
	}
	return dnsFailure(header, question)
}
func exchangeDNS(ctx context.Context, query []byte, server netip.Addr, luid winipcfg.LUID, tcp bool) ([]byte, error) {
	network := "udp"
	if tcp {
		network = "tcp"
	}
	conn, err := Dialer(luid).DialContext(ctx, network, net.JoinHostPort(server.String(), "53"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	if tcp {
		frame := make([]byte, len(query)+2)
		binary.BigEndian.PutUint16(frame, uint16(len(query)))
		copy(frame[2:], query)
		if _, err = conn.Write(frame); err != nil {
			return nil, err
		}
		if _, err = io.ReadFull(conn, frame[:2]); err != nil {
			return nil, err
		}
		answer := make([]byte, binary.BigEndian.Uint16(frame[:2]))
		_, err = io.ReadFull(conn, answer)
		return answer, err
	}
	if _, err = conn.Write(query); err != nil {
		return nil, err
	}
	answer := make([]byte, 65535)
	n, err := conn.Read(answer)
	return answer[:n], err
}
