//go:build !windows && cgo

package store

/*
#cgo linux LDFLAGS: -lsqlite3
#cgo darwin LDFLAGS: -lsqlite3
#include <stdlib.h>
#include <sqlite3.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

type cgoSQLite struct{ handle *C.sqlite3 }

func openNative(path string) (sqliteNative, error) {
	name := C.CString(path)
	defer C.free(unsafe.Pointer(name))
	var handle *C.sqlite3
	result := C.sqlite3_open_v2(name, &handle, C.SQLITE_OPEN_READWRITE|C.SQLITE_OPEN_CREATE|C.SQLITE_OPEN_FULLMUTEX, nil)
	if result != C.SQLITE_OK {
		if handle != nil {
			C.sqlite3_close_v2(handle)
		}
		return nil, fmt.Errorf("open SQLite: result %d", int(result))
	}
	return &cgoSQLite{handle: handle}, nil
}

func (database *cgoSQLite) Exec(statement string) error {
	encoded := C.CString(statement)
	defer C.free(unsafe.Pointer(encoded))
	var message *C.char
	result := C.sqlite3_exec(database.handle, encoded, nil, nil, &message)
	if result != C.SQLITE_OK {
		detail := C.GoString(C.sqlite3_errmsg(database.handle))
		if message != nil {
			detail = C.GoString(message)
			C.sqlite3_free(unsafe.Pointer(message))
		}
		return fmt.Errorf("SQLite exec (%d): %s", int(result), detail)
	}
	return nil
}

func (database *cgoSQLite) ScalarInt64(query string) (int64, error) {
	encoded := C.CString(query)
	defer C.free(unsafe.Pointer(encoded))
	var statement *C.sqlite3_stmt
	if result := C.sqlite3_prepare_v2(database.handle, encoded, -1, &statement, nil); result != C.SQLITE_OK {
		return 0, fmt.Errorf("prepare SQLite query: %s", C.GoString(C.sqlite3_errmsg(database.handle)))
	}
	defer C.sqlite3_finalize(statement)
	if result := C.sqlite3_step(statement); result != C.SQLITE_ROW {
		return 0, fmt.Errorf("step SQLite query: result %d", int(result))
	}
	return int64(C.sqlite3_column_int64(statement, 0)), nil
}

func (database *cgoSQLite) Close() error {
	if database.handle == nil {
		return nil
	}
	if result := C.sqlite3_close_v2(database.handle); result != C.SQLITE_OK {
		return fmt.Errorf("close SQLite: result %d", int(result))
	}
	database.handle = nil
	return nil
}
