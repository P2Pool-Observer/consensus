//go:build purego || !(gc && !tinygo)

package utils

import "net"

// InterfaceAddrs returns a list of unicast interface addresses for a specific
// interface.
func InterfaceAddrs(ifi *net.Interface) ([]*ExtendedIPNet, error) {
	return nil, nil
}
