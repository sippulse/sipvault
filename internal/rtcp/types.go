package rtcp

// PacketType identifies the RTCP packet type.
type PacketType uint8

const (
	TypeSenderReport   PacketType = 200
	TypeReceiverReport PacketType = 201
)

// Header is the common RTCP header (first 4 bytes of every RTCP packet).
type Header struct {
	Version    uint8
	Padding    bool
	Count      uint8      // RC (report count) or SC (source count)
	PacketType PacketType
	Length     uint16     // in 32-bit words minus one
}

// SenderInfo is the sender information block found in Sender Reports.
type SenderInfo struct {
	NTPTimestamp uint64
	RTPTimestamp uint32
	PacketCount  uint32
	OctetCount   uint32
}

// ReportBlock is a single report block within SR or RR packets.
type ReportBlock struct {
	SSRC             uint32
	FractionLost     uint8
	CumulativeLost   uint32 // 24 bits
	HighestSeq       uint32
	Jitter           uint32
	LastSR           uint32
	DelaySinceLastSR uint32
}

// SenderReport represents a parsed RTCP Sender Report (PT=200).
type SenderReport struct {
	SSRC       uint32
	SenderInfo SenderInfo
	Reports    []ReportBlock
}

// ReceiverReport represents a parsed RTCP Receiver Report (PT=201).
type ReceiverReport struct {
	SSRC    uint32
	Reports []ReportBlock
}

// Packet is a parsed RTCP packet.
type Packet struct {
	Header         Header
	SenderReport   *SenderReport
	ReceiverReport *ReceiverReport
}
