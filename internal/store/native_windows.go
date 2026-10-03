//go:build windows

package store

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	sqliteOK   = 0
	sqliteRow  = 100
	sqliteDone = 101
)

var (
	sqliteDLL      = syscall.NewLazyDLL("winsqlite3.dll")
	sqliteOpen     = sqliteDLL.NewProc("sqlite3_open_v2")
	sqliteClose    = sqliteDLL.NewProc("sqlite3_close_v2")
	sqliteExec     = sqliteDLL.NewProc("sqlite3_exec")
	sqliteFree     = sqliteDLL.NewProc("sqlite3_free")
	sqliteErrmsg   = sqliteDLL.NewProc("sqlite3_errmsg")
	sqlitePrepare  = sqliteDLL.NewProc("sqlite3_prepare_v2")
	sqliteStep     = sqliteDLL.NewProc("sqlite3_step")
	sqliteColumn   = sqliteDLL.NewProc("sqlite3_column_int64")
	sqliteText     = sqliteDLL.NewProc("sqlite3_column_text")
	sqliteBytes    = sqliteDLL.NewProc("sqlite3_column_bytes")
	sqliteFinalize = sqliteDLL.NewProc("sqlite3_finalize")
	kernel32DLL    = syscall.NewLazyDLL("kernel32.dll")
	lstrlenA       = kernel32DLL.NewProc("lstrlenA")
	rtlMoveMemory  = kernel32DLL.NewProc("RtlMoveMemory")
)

type windowsSQLite struct{ handle uintptr }

func openNative(path string) (sqliteNative, error) {
	name := append([]byte(path), 0)
	var handle uintptr
	result, _, callErr := sqliteOpen.Call(
		uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&handle)),
		uintptr(0x00000002|0x00000004|0x00010000), 0,
	)
	runtime.KeepAlive(name)
	if int32(result) != sqliteOK {
		if handle != 0 {
			sqliteClose.Call(handle)
		}
		return nil, fmt.Errorf("open SQLite: result %d: %v", int32(result), callErr)
	}
	return &windowsSQLite{handle: handle}, nil
}

func (database *windowsSQLite) Exec(statement string) error {
	encoded := append([]byte(statement), 0)
	var message uintptr
	result, _, _ := sqliteExec.Call(database.handle, uintptr(unsafe.Pointer(&encoded[0])), 0, 0, uintptr(unsafe.Pointer(&message)))
	runtime.KeepAlive(encoded)
	if int32(result) != sqliteOK {
		detail := database.errorMessage()
		if message != 0 {
			detail = bytePointerString(message)
			sqliteFree.Call(message)
		}
		return fmt.Errorf("SQLite exec (%d): %s", int32(result), detail)
	}
	return nil
}

func (database *windowsSQLite) ScalarInt64(query string) (int64, error) {
	encoded := append([]byte(query), 0)
	var statement uintptr
	result, _, _ := sqlitePrepare.Call(database.handle, uintptr(unsafe.Pointer(&encoded[0])), ^uintptr(0), uintptr(unsafe.Pointer(&statement)), 0)
	runtime.KeepAlive(encoded)
	if int32(result) != sqliteOK {
		return 0, fmt.Errorf("prepare SQLite query: %s", database.errorMessage())
	}
	defer sqliteFinalize.Call(statement)
	result, _, _ = sqliteStep.Call(statement)
	if int32(result) != sqliteRow {
		return 0, fmt.Errorf("step SQLite query: result %d: %s", int32(result), database.errorMessage())
	}
	value, _, _ := sqliteColumn.Call(statement, 0)
	return int64(value), nil
}

func (database *windowsSQLite) Close() error {
	if database.handle == 0 {
		return nil
	}
	result, _, _ := sqliteClose.Call(database.handle)
	database.handle = 0
	if int32(result) != sqliteOK {
		return fmt.Errorf("close SQLite: result %d", int32(result))
	}
	return nil
}

func (database *windowsSQLite) QueryStrings(query string, limit, maxBytes int) ([]string, error) {
	encoded := append([]byte(query), 0)
	var statement uintptr
	result, _, _ := sqlitePrepare.Call(database.handle, uintptr(unsafe.Pointer(&encoded[0])), ^uintptr(0), uintptr(unsafe.Pointer(&statement)), 0)
	runtime.KeepAlive(encoded)
	if int32(result) != sqliteOK {
		return nil, fmt.Errorf("prepare SQLite evidence query: result %d", int32(result))
	}
	defer sqliteFinalize.Call(statement)
	rows := make([]string, 0)
	total := 0
	for len(rows) < limit {
		result, _, _ = sqliteStep.Call(statement)
		if int32(result) == sqliteDone {
			break
		}
		if int32(result) != sqliteRow {
			return nil, fmt.Errorf("step SQLite evidence query: result %d", int32(result))
		}
		length, _, _ := sqliteBytes.Call(statement, 0)
		if length > 64<<10 {
			return nil, fmt.Errorf("SQLite evidence row exceeds limit")
		}
		if total+int(length) > maxBytes {
			break
		}
		pointer, _, _ := sqliteText.Call(statement, 0)
		contents := make([]byte, int(length))
		if length != 0 {
			if pointer == 0 {
				return nil, fmt.Errorf("SQLite evidence row has no text")
			}
			rtlMoveMemory.Call(uintptr(unsafe.Pointer(&contents[0])), pointer, length)
			runtime.KeepAlive(contents)
		}
		rows = append(rows, string(contents))
		total += len(contents)
	}
	return rows, nil
}

func (database *windowsSQLite) errorMessage() string {
	pointer, _, _ := sqliteErrmsg.Call(database.handle)
	return bytePointerString(pointer)
}

func bytePointerString(pointer uintptr) string {
	if pointer == 0 {
		return "unknown error"
	}
	length, _, _ := lstrlenA.Call(pointer)
	if length == 0 {
		return ""
	}
	if length > 4096 {
		length = 4096
	}
	bytes := make([]byte, int(length))
	rtlMoveMemory.Call(uintptr(unsafe.Pointer(&bytes[0])), pointer, length)
	runtime.KeepAlive(bytes)
	return string(bytes)
}
