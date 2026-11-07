module vault443

go 1.24.0

require github.com/godbus/dbus/v5 v5.1.0

require gopkg.in/yaml.v3 v3.0.1

require (
	github.com/BurntSushi/toml v0.4.1 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/lxn/walk v0.0.0-20210112085537-c389da54e794 // indirect
	github.com/lxn/win v0.0.0-20210218163916-a377121e959e // indirect
	github.com/tailscale/wf v0.0.0-20240214030419-6fbb0a674ee6 // indirect
	go4.org/netipx v0.0.0-20220725152314-7e7bdc8411bf // indirect
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/exp/typeparams v0.0.0-20220218215828-6cf2b201936e // indirect
	golang.org/x/mod v0.27.0 // indirect
	golang.org/x/net v0.44.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
	golang.org/x/text v0.29.0 // indirect
	golang.org/x/tools v0.36.0 // indirect
	golang.zx2c4.com/wireguard/windows v0.5.3 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2
	gopkg.in/Knetic/govaluate.v3 v3.0.0 // indirect
	honnef.co/go/tools v0.3.2 // indirect
)

// Reviewed Windows FWPM_FILTER0 ABI correction; upstream identity is retained
// in packaging/windows/wf-patch.json and bundled third-party notices.
replace github.com/tailscale/wf => ./third_party/wf
