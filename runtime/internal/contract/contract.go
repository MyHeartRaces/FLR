package contract

type Class string
type Channel string

const (
	Local       Class   = "local"
	Direct      Class   = "direct"
	General     Class   = "general"
	Games       Class   = "games"
	Down        Channel = "down"
	AWG         Channel = "awg"
	Gecko       Channel = "gecko"
	VLESS       Channel = "vless"
	ClassMask   uint32  = 0x0f000000
	ChannelMask uint32  = 0x70000000
	OuterMark   uint32  = 0x80000000
	ProbeMark   uint32  = 0x00800000
	OwnedMask   uint32  = 0xff800000
)

type Selection struct {
	General Channel `json:"general"`
	Games   Channel `json:"games"`
}

func ClassMark(c Class) uint32 {
	switch c {
	case General:
		return 0x01000000
	case Games:
		return 0x02000000
	case Direct:
		return 0x03000000
	}
	return 0
}
func ChannelMark(c Channel) uint32 {
	switch c {
	case AWG:
		return 0x10000000
	case Gecko:
		return 0x20000000
	case VLESS:
		return 0x30000000
	}
	return 0
}
func Table(c Channel) int {
	switch c {
	case AWG:
		return 770
	case Gecko:
		return 771
	case VLESS:
		return 772
	}
	return 0
}
