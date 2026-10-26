package network

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	"vault443/internal/core"
	"vault443/internal/model"
)

// VPNCompatibility inspects fresh kernel/process metadata even while VLESS is
// stopped. It neither calls load (which restores runtime state) nor uses any
// mutating command. Inspection must not hold the controller lock during I/O.
func (m *Manager) VPNCompatibility(ctx context.Context) model.VPNCompatibility {
	out := model.VPNCompatibility{Items: []model.VPNCompatibilityItem{}}
	if !m.inspectionMu.TryLock() {
		out.Message = "Проверка других VPN уже выполняется. Повторите через несколько секунд."
		return out
	}
	defer m.inspectionMu.Unlock()
	if !m.mu.TryLock() {
		out.Message = "Состояние VPN меняется. Проверка повторится через несколько секунд."
		return out
	}
	bindings := append([]Binding(nil), m.bindings...)
	loaded, config, r := m.loaded, m.config, m.r
	m.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if !loaded {
		if err := readPrivateState(config.StateDir, "vpn-bindings.json", &bindings); err != nil {
			out.Message = compatibilityMessage(err)
			return out
		}
		for _, b := range bindings {
			data, _ := json.Marshal(b)
			if _, err := ParseBinding(string(data)); err != nil {
				out.Message = "Сохранённая ручная привязка повреждена. Проверьте диагностику."
				return out
			}
		}
	}
	s, err := collect(ctx, r)
	if err != nil {
		out.Message = "Не удалось прочитать интерфейсы и маршруты. Проверьте диагностику и доступность службы."
		if ctx.Err() != nil {
			out.Message = compatibilityMessage(ctx.Err())
		}
		return out
	}
	var automatic []Binding
	_, liveRunner := r.(execRunner)
	if !config.DryRun && liveRunner {
		automatic, err = automaticBindings(ctx, r, s, bindings)
	}
	out = inspectCompatibility(ctx, r, s, bindings, automatic)
	if err != nil {
		out.Message = compatibilityMessage(err)
	}
	if ctx.Err() != nil {
		out.Message = compatibilityMessage(ctx.Err())
	}
	return out
}

// Each binding goes through the same validation as the routing controller.
// Restrict only the links inspected by its final unknown-interface check, so a
// failed tunnel cannot hide the independently verified rows in this UI report.
func inspectCompatibility(ctx context.Context, r runner, s Snapshot, manual, automatic []Binding) model.VPNCompatibility {
	out := model.VPNCompatibility{Items: []model.VPNCompatibilityItem{}}
	seen := map[string]bool{}
	for _, group := range []struct {
		source   string
		bindings []Binding
	}{{"manual", manual}, {"automatic", automatic}} {
		for _, b := range group.bindings {
			if !core.SafeInterface(b.Interface) || b.Interface == TunName || seen[b.Interface] {
				continue
			}
			seen[b.Interface] = true
			l, present := s.Link(b.Interface)
			item := model.VPNCompatibilityItem{Interface: b.Interface, Manager: b.Manager, Application: vpnApplication(b.Manager), Source: group.source, Active: present}
			// Observed routes are separate from verification: an unverified full
			// tunnel must never be interpreted as permission to bypass protection.
			routes := routesFor(s, b.Interface)
			item.FullIPv4 = claimsDefault(routes, 4)
			item.FullIPv6 = claimsDefault(routes, 6)
			only := s
			only.Links = nil
			if present {
				only.Links = []Link{l}
			}
			if ctx.Err() != nil {
				item.Message = compatibilityMessage(ctx.Err())
			} else if verified, err := detectExternal(ctx, r, only, []Binding{b}); err != nil {
				item.Message = compatibilityMessage(err)
			} else if !present {
				item.Message = "Интерфейс отсутствует; проверка повторится после его появления."
			} else {
				item.Verified = len(verified) == 1 && verified[0].Active
				if !item.Verified {
					item.Message = "Не удалось подтвердить активное подключение."
				}
			}
			out.Items = append(out.Items, item)
		}
	}
	for _, l := range s.Links {
		if l.Name == TunName || !isTunnel(l) || !core.SafeInterface(l.Name) || seen[l.Name] {
			continue
		}
		routes := routesFor(s, l.Name)
		out.Items = append(out.Items, model.VPNCompatibilityItem{
			Interface: l.Name, Manager: "unknown", Application: "Неизвестный VPN", Source: "unknown", Active: true,
			FullIPv4: claimsDefault(routes, 4), FullIPv6: claimsDefault(routes, 6),
			Message: "Не подтверждена связь туннеля с доверенным процессом и транспортом OpenVPN или метаданными WireGuard. Нужна диагностика или ручная привязка.",
		})
	}
	sort.Slice(out.Items, func(i, j int) bool { return out.Items[i].Interface < out.Items[j].Interface })
	return out
}

func routesFor(s Snapshot, name string) []Route {
	var routes []Route
	for _, route := range s.Routes {
		if route.Device == name && !route.owned() {
			routes = append(routes, route)
		}
	}
	return routes
}

func vpnApplication(manager string) string {
	switch manager {
	case "pritunl":
		return "Pritunl"
	case "openvpn":
		return "OpenVPN"
	case "networkmanager":
		return "NetworkManager"
	case "wg-quick":
		return "WireGuard"
	default:
		return "Неизвестный VPN"
	}
}

// Never serialize arbitrary command errors, process arguments, or paths.
func compatibilityMessage(err error) string {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "Проверка других VPN не завершилась вовремя. Повторите попытку."
	}
	switch err.Error() {
	case "enrolled VPN interface is not a TUN/WireGuard device":
		return "Интерфейс ручной привязки больше не является VPN-туннелем."
	case "cannot verify enrolled VPN service", "enrolled VPN service has no trusted cgroup":
		return "Не удалось подтвердить системную службу, которой принадлежит туннель."
	case "enrolled NetworkManager VPN is not connected":
		return "NetworkManager не подтверждает активное подключение этого туннеля."
	case "cannot verify OpenVPN transport sockets":
		return "Не удалось прочитать транспортные соединения OpenVPN. Проверьте права службы."
	case "cannot inspect VPN process ownership":
		return "Не удалось проверить владельцев процессов VPN. Проверьте права службы."
	case "OpenVPN transport endpoints need a trusted cgroup or systemd unit":
		return "Для транспорта OpenVPN не подтверждена системная служба или группа процессов."
	case "cannot inspect WireGuard routing mark", "cannot parse WireGuard routing mark", "cannot verify WireGuard transport mark", "WireGuard endpoint mark does not match its interface":
		return "Не удалось подтвердить метку транспорта WireGuard."
	case "cannot inspect WireGuard listen port", "cannot verify WireGuard listen port", "unmarked WireGuard needs its verified UDP listen port", "WireGuard has no established transport socket":
		return "Не удалось подтвердить UDP-порт транспорта WireGuard."
	case "cannot inspect WireGuard transport endpoints", "WireGuard has no verified transport endpoints":
		return "У WireGuard нет подтверждённых адресов транспортного соединения."
	case "cannot inspect service state", "service state permissions are unsafe", "cannot read service state", "invalid persisted network state":
		return "Не удалось безопасно прочитать сохранённые ручные привязки. Проверьте диагностику."
	default:
		return "Проверка туннеля не пройдена. Откройте диагностику для проверки настроек службы."
	}
}

func readPrivateState(dir, name string, target any) error {
	path := filepath.Join(dir, name)
	fi, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.New("cannot inspect service state")
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0077 != 0 {
		return errors.New("service state permissions are unsafe")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return errors.New("cannot read service state")
	}
	if err = json.Unmarshal(b, target); err != nil {
		return errors.New("invalid persisted network state")
	}
	return nil
}
