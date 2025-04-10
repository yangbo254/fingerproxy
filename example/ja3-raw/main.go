package main

import (
	"fmt"

	"github.com/dreadl0ck/tlsx"
	"github.com/yangbo254/fingerproxy"
	"github.com/yangbo254/fingerproxy/pkg/fingerprint"
	"github.com/yangbo254/fingerproxy/pkg/ja3"
	"github.com/yangbo254/fingerproxy/pkg/metadata"
	"github.com/yangbo254/fingerproxy/pkg/reverseproxy"
)

func main() {
	fingerproxy.GetHeaderInjectors = func() []reverseproxy.HeaderInjector {
		i := fingerproxy.DefaultHeaderInjectors()
		i = append(i, fingerprint.NewFingerprintHeaderInjector(
			"X-JA3-Raw-Fingerprint",
			fpJA3Raw,
		))
		return i
	}
	fingerproxy.Run()
}

func fpJA3Raw(data *metadata.Metadata) (string, error) {
	hellobasic := &tlsx.ClientHelloBasic{}
	if err := hellobasic.Unmarshal(data.ClientHelloRecord); err != nil {
		return "", fmt.Errorf("ja3: %w", err)
	}

	fp := string(ja3.Bare(hellobasic))

	return fp, nil
}
