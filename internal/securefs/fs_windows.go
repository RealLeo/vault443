package securefs

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows has no Unix permission bits. Every private path is instead protected
// by an inheritable DACL; production storage is accessible only to SYSTEM/admins.
const NoFollow = 0
const NonBlock = 0

func currentSID() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}
func Owner(testing bool) (int, error) {
	if testing {
		return -1, nil
	}
	sid, err := currentSID()
	if err != nil || sid != "S-1-5-18" {
		return 0, errors.New("the Windows system daemon must run as LocalSystem")
	}
	return 0, nil
}
func Check(info os.FileInfo, path string, owner int, private bool) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("reparse points are not allowed")
	}
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(path16)
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("reparse points are not allowed")
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	allowed := map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true}
	if !private {
		if sid, _, _, e := windows.LookupSID("", `NT SERVICE\TrustedInstaller`); e == nil {
			allowed[sid.String()] = true
		}
	}
	if owner == -1 {
		sid, e := currentSID()
		if e != nil {
			return e
		}
		allowed[sid] = true
	}
	fileOwner, _, err := sd.Owner()
	if err != nil || !allowed[fileOwner.String()] {
		return errors.New("private path is not owned by a trusted account")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.New("path needs a restrictive DACL")
	}
	// On ancestors, creation of unrelated children does not confer access to an
	// existing protected child (ProgramData intentionally allows that creation).
	mask := windows.ACCESS_MASK(windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | 0x40 | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.GENERIC_WRITE | windows.GENERIC_ALL)
	if !private && info.IsDir() {
		mask &^= windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA
	}
	if private {
		mask |= windows.FILE_READ_DATA | windows.FILE_EXECUTE | windows.GENERIC_READ | windows.GENERIC_WRITE | windows.GENERIC_ALL
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err = windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !allowed[sid.String()] && ace.Mask&mask != 0 {
			return errors.New("path grants access to an untrusted account")
		}
	}
	return nil
}
func MkdirAll(path string, _ os.FileMode) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("private path is not a directory")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(path)
	if parent == path {
		return errors.New("missing volume root")
	}
	if err := MkdirAll(parent, 0700); err != nil {
		return err
	}
	sid, err := currentSID()
	if err != nil {
		return err
	}
	sddl := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	if sid != "S-1-5-18" {
		sddl += "(A;OICI;FA;;;" + sid + ")"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	err = windows.CreateDirectory(p, &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd})
	if err == windows.ERROR_ALREADY_EXISTS {
		return nil
	}
	return err
}
func OpenFile(path string, flags int, mode os.FileMode) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	access := uint32(windows.GENERIC_READ)
	if flags&os.O_RDWR != 0 {
		access |= windows.GENERIC_WRITE
	}
	if flags&os.O_WRONLY != 0 {
		access = windows.GENERIC_WRITE
	}
	if flags&os.O_APPEND != 0 {
		access |= windows.GENERIC_WRITE
	}
	creation := uint32(windows.OPEN_EXISTING)
	if flags&os.O_CREATE != 0 {
		creation = windows.OPEN_ALWAYS
	}
	if flags&os.O_EXCL != 0 {
		creation = windows.CREATE_NEW
	}
	if flags&os.O_TRUNC != 0 {
		creation = windows.CREATE_ALWAYS
	}
	h, err := windows.CreateFile(p, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, creation, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(h, &info); err != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		windows.CloseHandle(h)
		return nil, errors.New("private file must be a regular file without reparse points")
	}
	file := os.NewFile(uintptr(h), path)
	// The exclusively locked daemon has one serialized journal writer. Keeping
	// GENERIC_WRITE permits FlushFileBuffers; an append-only access mask does not.
	if flags&os.O_APPEND != 0 {
		if _, err = file.Seek(0, 2); err != nil {
			file.Close()
			return nil, err
		}
	}
	return file, nil
}
func Lock(file *os.File) error {
	return windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
}

// MoveFileEx WRITE_THROUGH is the Windows metadata durability boundary. Directory
// handles cannot be fsynced like Linux directory descriptors.
func SyncDir(_ *os.File) error { return nil }
func Replace(from, to string) error {
	a, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	b, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(a, b, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
