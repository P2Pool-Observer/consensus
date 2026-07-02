//go:build goexperiment.runtimesecret

package crypto

import "runtime/secret"

func ZeroizingSecretDo(f func()) {
	secret.Do(f)
}
