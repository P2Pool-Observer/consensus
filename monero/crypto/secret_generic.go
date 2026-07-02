//go:build !goexperiment.runtimesecret

package crypto

func ZeroizingSecretDo(f func()) {
	f()
}
