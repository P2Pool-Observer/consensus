package rpc

import "testing"

func TestDigestWiki(t *testing.T) {
	d := newDigest("Digest realm=\"testrealm@host.com\",qop=\"auth\",nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"")
	if d == nil {
		t.Fatal("nil digest")
	}

	hdr, err := d.Auth("GET", "/dir/index.html", "Mufasa", "Circle Of Life", 1, "0a4f113b")
	if err != nil {
		t.Fatal(err)
	}

	const expected = "Digest username=\"Mufasa\",realm=\"testrealm@host.com\",nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",uri=\"/dir/index.html\",qop=auth,nc=00000001,cnonce=\"0a4f113b\",response=\"6629fae49393a05397450978507c4ef1\",opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""
	if hdr != expected {
		t.Logf("expected %s", expected)
		t.Logf("received %s", hdr)
		t.Fatal()
	}
}

func TestDigestMonero(t *testing.T) {
	d := newDigest("Digest qop=\"auth\",algorithm=MD5,realm=\"monero-rpc\",nonce=\"G62IXz7aFqwZ63LiWtPM2w==\",stale=false\n")
	if d == nil {
		t.Fatal("nil digest")
	}

	hdr, err := d.Auth("POST", "/get_transactions", "test", "test2", 1, "iBqAWAc3zv/jygm5")
	if err != nil {
		t.Fatal(err)
	}

	const expected = "Digest username=\"test\",realm=\"monero-rpc\",nonce=\"G62IXz7aFqwZ63LiWtPM2w==\",uri=\"/get_transactions\",qop=auth,nc=00000001,cnonce=\"iBqAWAc3zv/jygm5\",response=\"330b5cc88abe5745a514f931218eb5ff\",algorithm=MD5"
	if hdr != expected {
		t.Logf("expected %s", expected)
		t.Logf("received %s", hdr)
		t.Fatal()
	}
}
