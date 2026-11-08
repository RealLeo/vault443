package installpath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
	"vault443/internal/securefs"
)

const uninstallKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B7547E6A-E316-4C92-9407-1B0F0D4A3443}_is1`
const directorySDDL = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"

// Registered returns only the machine-wide installer registration. Unprivileged
// per-user registry data cannot redirect an elevated update.
func Registered() (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer key.Close()
	location, _, err := key.GetStringValue("InstallLocation")
	if err != nil {
		return "", fmt.Errorf("cannot read the existing installation location: %w", err)
	}
	return Canonical(location)
}

func localVolume(path string) error {
	root, _ := windows.UTF16PtrFromString(path[:3])
	if windows.GetDriveType(root) != 3 { // DRIVE_FIXED, not a mapped/removable drive
		return errors.New("installation requires a fixed local drive")
	}
	var flags uint32
	if err := windows.GetVolumeInformation(root, nil, 0, nil, nil, &flags, nil, 0); err != nil {
		return err
	}
	if flags&8 == 0 { // FILE_PERSISTENT_ACLS
		return errors.New("installation drive must support persistent Windows access permissions")
	}
	drive, _ := windows.UTF16PtrFromString(path[:2])
	var device [512]uint16
	_, err := windows.QueryDosDevice(drive, &device[0], uint32(len(device)))
	deviceName := windows.UTF16ToString(device[:])
	volume := strings.TrimPrefix(deviceName, `\Device\HarddiskVolume`)
	if err != nil || volume == deviceName || volume == "" || strings.IndexFunc(volume, func(c rune) bool { return c < '0' || c > '9' }) >= 0 {
		return errors.New("installation requires a persistent volume drive, not a SUBST/device alias")
	}
	// SCM resolves DOS drive letters in the machine namespace. A per-user raw
	// DOS alias must not make the installer validate a different volume from the
	// one LocalSystem will execute at boot. Mount-manager assignments are global.
	var volumeName [64]uint16
	if err = windows.GetVolumeNameForVolumeMountPoint(root, &volumeName[0], uint32(len(volumeName))); err != nil {
		return err
	}
	names := make([]uint16, 4096)
	var needed uint32
	err = windows.GetVolumePathNamesForVolumeName(&volumeName[0], &names[0], uint32(len(names)), &needed)
	if errors.Is(err, windows.ERROR_MORE_DATA) && needed > uint32(len(names)) && needed <= 65536 {
		names = make([]uint16, needed)
		err = windows.GetVolumePathNamesForVolumeName(&volumeName[0], &names[0], uint32(len(names)), &needed)
	}
	if err != nil {
		return err
	}
	for start := 0; start < len(names) && names[start] != 0; {
		end := start
		for end < len(names) && names[end] != 0 {
			end++
		}
		if strings.EqualFold(windows.UTF16ToString(names[start:end]), path[:3]) {
			return nil
		}
		start = end + 1
	}
	return errors.New("installation drive is not a persistent machine volume assignment")
}

// lock opens the object itself, never a final-component reparse point. Omitting
// FILE_SHARE_DELETE prevents rename/deletion throughout the top-down check. Once
// checks finish, owner/DACL and DELETE_CHILD checks prevent an ordinary user from
// replacing any component during the subsequent installer copy.
func lock(path string, directory bool) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, err
	}
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(h, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		(directory != (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0)) {
		windows.CloseHandle(h)
		return 0, errors.New("installation path is not an ordinary file/directory")
	}
	return h, nil
}

func closeHandles(handles []windows.Handle) {
	for i := len(handles) - 1; i >= 0; i-- {
		windows.CloseHandle(handles[i])
	}
}

func check(path string, h windows.Handle, target bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if err = securefs.Check(info, path, 0, false); err != nil {
		return err
	}
	// Ancestors may allow creation of unrelated children (e.g. ProgramData).
	// The executable-containing directory itself must not allow new DLLs/files.
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.New("installation directory requires a restrictive DACL")
	}
	trustedInstaller, _, _, _ := windows.LookupSID("", `NT SERVICE\TrustedInstaller`)
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err = windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			// Unknown conditional/object allow ACEs must not bypass the ordinary
			// SID/write-mask checks. Deny ACEs cannot grant access.
			if ace.Header.AceType == 1 || ace.Header.AceType == 6 || ace.Header.AceType == 10 || ace.Header.AceType == 12 {
				continue
			}
			return errors.New("installation path contains an unsupported access rule")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		trusted := sid == "S-1-5-18" || sid == "S-1-5-32-544" || (trustedInstaller != nil && sid == trustedInstaller.String())
		if !trusted && ace.Mask&(windows.FILE_WRITE_EA|windows.FILE_WRITE_ATTRIBUTES) != 0 {
			return errors.New("installation path allows untrusted metadata changes")
		}
		if target && !trusted && ace.Mask&(windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA) != 0 {
			return errors.New("installation directory allows untrusted child creation")
		}
	}
	return nil
}

func checkTree(path string) error {
	var handles []windows.Handle
	defer func() { closeHandles(handles) }()
	return filepath.WalkDir(path, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		h, err := lock(current, entry.IsDir())
		if err != nil {
			return fmt.Errorf("cannot lock existing installation object %s: %w", current, err)
		}
		handles = append(handles, h)
		if err = check(current, h, entry.IsDir()); err != nil {
			return fmt.Errorf("unsafe existing installation object %s: %w", current, err)
		}
		return nil
	})
}

// CheckDirectory is a read-only counterpart used by native acceptance and by
// an administrator checking the effective protection of an installation.
func CheckDirectory(path string) error {
	path, err := Canonical(path)
	if err != nil {
		return err
	}
	if err = localVolume(path); err != nil {
		return err
	}
	var handles []windows.Handle
	defer func() { closeHandles(handles) }()
	parts := chain(path)
	for i, current := range parts {
		h, err := lock(current, true)
		if err != nil {
			return fmt.Errorf("cannot lock installation directory %s: %w", current, err)
		}
		handles = append(handles, h)
		if err = check(current, h, i == len(parts)-1); err != nil {
			return fmt.Errorf("unsafe installation directory %s: %w", current, err)
		}
	}
	return checkTree(path)
}

func chain(path string) []string {
	result := []string{path[:3]}
	for _, part := range strings.Split(path[3:], `\`) {
		result = append(result, filepath.Join(result[len(result)-1], part))
	}
	return result
}

// CheckExecutable is also enforced immediately before registering the daemon
// with SCM. The caller cannot install an elevated service from a writable path.
func CheckExecutable(path string) error {
	path, err := Canonical(path)
	if err != nil {
		return err
	}
	if err = localVolume(path); err != nil {
		return err
	}
	var handles []windows.Handle
	defer func() { closeHandles(handles) }()
	parts := chain(path)
	for i, current := range parts {
		h, err := lock(current, i != len(parts)-1)
		if err != nil {
			return fmt.Errorf("cannot lock installed path %s: %w", current, err)
		}
		handles = append(handles, h)
		if err = check(current, h, i == len(parts)-2); err != nil {
			return fmt.Errorf("unsafe installed path %s: %w", current, err)
		}
	}
	return nil
}

// Prepare creates missing directories only. Existing parents and targets are
// never re-owned or re-ACL'd. A nonempty target is accepted solely for the exact
// machine-registered installation, whose protected files are checked first.
func Prepare(path string) (err error) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("administrator approval is required")
	}
	path, err = Canonical(path)
	if err != nil {
		return err
	}
	if err = localVolume(path); err != nil {
		return err
	}
	registered, err := Registered()
	if err != nil {
		return err
	}
	if registered != "" && !strings.EqualFold(registered, path) {
		return errors.New("updates keep the existing location; uninstall with profiles retained before moving")
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, serviceErr := manager.OpenService("Vault443")
	if serviceErr == nil {
		defer service.Close()
		config, e := service.Config()
		if e != nil {
			return e
		}
		args, e := windows.DecomposeCommandLine(config.BinaryPathName)
		if e != nil || len(args) != 1 || !strings.EqualFold(args[0], filepath.Join(path, "vault443d.exe")) {
			return errors.New("the existing service uses another installation location")
		}
	} else if !errors.Is(serviceErr, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return serviceErr
	}
	sd, err := windows.SecurityDescriptorFromString(directorySDDL)
	if err != nil {
		return err
	}
	var handles []windows.Handle
	var created []string
	defer func() {
		closeHandles(handles)
		if err != nil {
			for i := len(created) - 1; i >= 0; i-- {
				_ = os.Remove(created[i]) // only a directory we created, and only empty
			}
		}
	}()
	parts := chain(path)
	for i, current := range parts {
		h, e := lock(current, true)
		if errors.Is(e, windows.ERROR_FILE_NOT_FOUND) || errors.Is(e, windows.ERROR_PATH_NOT_FOUND) {
			p, _ := windows.UTF16PtrFromString(current)
			e = windows.CreateDirectory(p, &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd})
			if e != nil {
				return fmt.Errorf("cannot create a protected installation directory: %w", e)
			}
			created = append(created, current)
			h, e = lock(current, true)
		}
		if e != nil {
			return fmt.Errorf("cannot lock installation directory %s: %w", current, e)
		}
		handles = append(handles, h)
		if e = check(current, h, i == len(parts)-1); e != nil {
			return fmt.Errorf("unsafe installation directory %s: %w", current, e)
		}
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != 0 && !strings.EqualFold(registered, path) {
		return errors.New("choose an empty directory or the registered Vault 443 location")
	}
	if len(entries) != 0 {
		if err = checkTree(path); err != nil {
			return err
		}
		return CheckExecutable(filepath.Join(path, "vault443d.exe"))
	}
	return nil
}
