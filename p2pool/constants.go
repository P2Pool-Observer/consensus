package p2pool

// MaxBufferSize Largest packet that can be sent over the wire
// pool block templates must also be below this size (with some fewer bytes due to packet overhead)
const MaxBufferSize = 128 * 1024
