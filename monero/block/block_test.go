package block

import (
	"bytes"
	"encoding/hex"
	"os"
	"path"
	"runtime"
	"testing"
)

func init() {
	_, filename, _, _ := runtime.Caller(0)
	// The ".." may change depending on you folder structure
	dir := path.Join(path.Dir(filename), "../..")
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}
}

var fuzzPoolBlocks = []string{
	"testdata/v4_block.dat",
	"testdata/v2_block.dat",
	"testdata/v1_mainnet_test2_block.dat",
}

func FuzzMainBlockRoundTrip(f *testing.F) {

	for _, path := range fuzzPoolBlocks {
		data, err := os.ReadFile(path)
		if err != nil {
			f.Fatal(err)
		}
		reader := bytes.NewReader(data)
		b := &Block{}
		err = b.FromReader(reader, false, nil)
		if err != nil {
			f.Skipf("leftover error: %s", err)
		}
		buf, err := b.MarshalBinary()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(buf)
	}

	f.Fuzz(func(t *testing.T, buf []byte) {
		b := &Block{}
		reader := bytes.NewReader(buf)
		err := b.FromReader(reader, false, nil)
		if err != nil {
			t.Skipf("leftover error: %s", err)
		}
		if reader.Len() > 0 {
			//clamp comparison
			buf = buf[:len(buf)-reader.Len()]
		}

		data, err := b.MarshalBinary()
		if err != nil {
			t.Fatalf("failed to marshal decoded block: %s", err)
			return
		}
		if !bytes.Equal(data, buf) {
			t.Logf("EXPECTED (len %d):\n%s", len(buf), hex.Dump(buf))
			t.Logf("ACTUAL (len %d):\n%s", len(data), hex.Dump(data))
			t.Fatalf("mismatched roundtrip")
		}
	})
}

func TestDecode(t *testing.T) {
	buf, err := hex.DecodeString("10108285b1c506d83b4becc05e46a51cb840d2fc4586ebb6a90ceb9bbebc07a06466262503087f0000000002ceded40101ff92ded4010180c8b29dc61103b3bb787bbd3e971cb725d191e0e992af6f5562c3e8b476b38656c223356a9e620d57032100f8adcf9de6feab2325c04630d40cf25b4fae058699332bf20d1dec0f91344a2549010000b616b8570000000002ac74c2da9fe06b4981971a3b8326a48904394b7402110000000000000000000000000000000000000632262e382526ed0f89631fab8280565f0b6c0816aaa5dc3266488ba07bcf250a1e81fa490701cacbeba8c3848a33cbf4d7dd216f84b273e31283acc28cb1aa21e2f15eef03b497e110c5958d1ea962fdc5d92038bb591678b406a20d4990f4c86b7a184eb723592b8a6a133102cacea588a500035e3a65209184443474a04df7a9e2cdf9536c62ab292bc3909c88f632ecdc3e3d2ef606d9a8cd54fe4d3926528c5a5015c17790fe18d25dc3195a849fe225172eb96a068b9b74fcea0168d8a3")
	if err != nil {
		t.Fatal(err)
	}
	b := &Block{}
	err = b.FromReader(bytes.NewReader(buf), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", b)
}
