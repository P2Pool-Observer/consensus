package monero

const (
	BlockTime = 60 * 2

	TransactionUnlockTime = 10
	MinerRewardUnlockTime = 60

	TailEmissionReward = 600000000000

	RequiredMajor         = 3
	RequiredMinor         = 10
	RequiredMoneroVersion = (RequiredMajor << 16) | RequiredMinor
	RequiredMoneroString  = "v0.18.0.0"
)

const (
	MainNetwork  = 18
	TestNetwork  = 53
	StageNetwork = 24

	SubAddressMainNetwork  = 42
	SubAddressTestNetwork  = 63
	SubAddressStageNetwork = 36

	IntegratedMainNetwork  = 19
	IntegratedTestNetwork  = 54
	IntegratedStageNetwork = 25
)
