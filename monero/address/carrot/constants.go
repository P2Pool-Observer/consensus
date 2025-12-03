package carrot

// Carrot addressing protocol domain separators
const (
	DomainSeparatorAmountBlindingFactor    = "Carrot commitment mask"
	DomainSeparatorOneTimeExtensionG       = "Carrot key extension G"
	DomainSeparatorOneTimeExtensionT       = "Carrot key extension T"
	DomainSeparatorEncryptionMaskAnchor    = "Carrot encryption mask anchor"
	DomainSeparatorEncryptionMaskAmount    = "Carrot encryption mask a"
	DomainSeparatorEncryptionMaskPaymentId = "Carrot encryption mask pid"
	DomainSeparatorJanusAnchorSpecial      = "Carrot janus anchor special"
	DomainSeparatorEphemeralPrivateKey     = "Carrot sending key normal"
	DomainSeparatorViewTag                 = "Carrot view tag"
	DomainSeparatorSenderReceiverSecret    = "Carrot sender-receiver secret"

	DomainSeparatorInputContextCoinbase = 'C'
	DomainSeparatorInputContextRingCT   = 'R'
)

// Carrot account secret domain separators
const (
	DomainSeparatorProveSpendKey               = "Carrot prove-spend key"
	DomainSeparatorViewBalanceSecret           = "Carrot view-balance secret"
	DomainSeparatorGenerateImageKey            = "Carrot generate-image key"
	DomainSeparatorGenerateImagePreimageSecret = "Carrot generate-image preimage secret"
	DomainSeparatorIncomingViewKey             = "Carrot incoming view key"
	DomainSeparatorGenerateAddressSecret       = "Carrot generate-address secret"
)

// Carrot address domain separators
const (
	DomainSeparatorAddressIndexPreimage1 = "Carrot address index preimage 1"
	DomainSeparatorAddressIndexPreimage2 = "Carrot address index preimage 2"
	DomainSeparatorSubaddressScalar      = "Carrot subaddress scalar"
)

// PersonalString Carrot Blake2b personal string
const PersonalString = "Monero"
