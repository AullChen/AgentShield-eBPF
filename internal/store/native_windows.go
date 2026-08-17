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
	sqliteFinalize = sqliteDLL.NewProc("sqlite3_finalize")
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

func (database *windowsSQLite) errorMessage() string {
	pointer, _, _ := sqliteErrmsg.Call(database.handle)
	return bytePointerString(pointer)
}

func bytePointerString(pointer uintptr) string {
	if pointer == 0 {
		return "unknown error"
	}
	bytes := make([]byte, 0, 128)
	for index := uintptr(0); index < 4096; index++ {
		value := *(*byte)(unsafe.Pointer(pointer + index))
		if value == 0 {
			break
		}
		bytes = append(bytes, value)
	}
	return string(bytes)
}
