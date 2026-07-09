package auth

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// syscallSocketpair creates a pair of connected Unix domain sockets.
func syscallSocketpair() ([]*os.File, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	return []*os.File{
		os.NewFile(uintptr(fds[0]), "socket0"),
		os.NewFile(uintptr(fds[1]), "socket1"),
	}, nil
}

// fdToUnixConn converts an *os.File to a *net.UnixConn.
func fdToUnixConn(f *os.File) (*net.UnixConn, error) {
	conn, err := net.FileConn(f)
	if err != nil {
		return nil, err
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("expected *net.UnixConn, got %T", conn)
	}
	return unixConn, nil
}
