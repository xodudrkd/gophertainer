package main

import (
	"sync"
)

// BufferPool manages reusable byte buffers for performance optimization
type BufferPool struct {
	pool sync.Pool
	size int
}

// NewBufferPool creates a new buffer pool with specified buffer size
func NewBufferPool(size int) *BufferPool {
	return &BufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, size)
			},
		},
		size: size,
	}
}

// Get retrieves a buffer from the pool
func (bp *BufferPool) Get() []byte {
	return bp.pool.Get().([]byte)[:0] // Reset length to 0
}

// Put returns a buffer to the pool
func (bp *BufferPool) Put(buf []byte) {
	if cap(buf) == bp.size {
		bp.pool.Put(buf)
	}
}

// StringPool manages reusable string builders
type StringPool struct {
	pool sync.Pool
}

// NewStringPool creates a new string pool
func NewStringPool() *StringPool {
	return &StringPool{
		pool: sync.Pool{
			New: func() interface{} {
				return make([]string, 0, 16)
			},
		},
	}
}

// Get retrieves a string slice from the pool
func (sp *StringPool) Get() []string {
	return sp.pool.Get().([]string)[:0]
}

// Put returns a string slice to the pool
func (sp *StringPool) Put(slice []string) {
	if cap(slice) <= 64 { // Avoid keeping very large slices
		sp.pool.Put(slice)
	}
}

// IPAllocatorPool manages reusable IP allocators for better memory efficiency
type IPAllocatorPool struct {
	pool sync.Pool
}

// NewIPAllocatorPool creates a new IP allocator pool
func NewIPAllocatorPool() *IPAllocatorPool {
	return &IPAllocatorPool{
		pool: sync.Pool{
			New: func() interface{} {
				return &IPAllocator{
					used4:   make(map[string]string),
					used6:   make(map[string]string),
					counter: nil, // Will be initialized when needed
				}
			},
		},
	}
}

// Get retrieves an IP allocator from the pool
func (iap *IPAllocatorPool) Get() *IPAllocator {
	allocator := iap.pool.Get().(*IPAllocator)
	// Reset the allocator state
	for k := range allocator.used4 {
		delete(allocator.used4, k)
	}
	for k := range allocator.used6 {
		delete(allocator.used6, k)
	}
	allocator.network4 = nil
	allocator.network6 = nil
	allocator.bitmap4 = nil
	allocator.baseAddr4 = 0
	allocator.maxAddrs4 = 0
	allocator.nextFree4 = 0
	allocator.counter = nil
	return allocator
}

// Put returns an IP allocator to the pool
func (iap *IPAllocatorPool) Put(allocator *IPAllocator) {
	if allocator != nil {
		iap.pool.Put(allocator)
	}
}

// Global pools for system-wide usage
var (
	// Buffer pools for different sizes
	smallBufferPool  = NewBufferPool(DefaultBufferSize)     // 64KB
	mediumBufferPool = NewBufferPool(NetworkBufferSize * 4) // 128KB  
	largeBufferPool  = NewBufferPool(DefaultBufferSize * 8) // 512KB
	
	// String pool for temporary string operations
	globalStringPool = NewStringPool()
	
	// IP allocator pool
	globalIPAllocatorPool = NewIPAllocatorPool()
)

// GetSmallBuffer retrieves a small buffer (64KB)
func GetSmallBuffer() []byte {
	return smallBufferPool.Get()
}

// PutSmallBuffer returns a small buffer to the pool
func PutSmallBuffer(buf []byte) {
	smallBufferPool.Put(buf)
}

// GetMediumBuffer retrieves a medium buffer (128KB)
func GetMediumBuffer() []byte {
	return mediumBufferPool.Get()
}

// PutMediumBuffer returns a medium buffer to the pool
func PutMediumBuffer(buf []byte) {
	mediumBufferPool.Put(buf)
}

// GetLargeBuffer retrieves a large buffer (512KB)
func GetLargeBuffer() []byte {
	return largeBufferPool.Get()
}

// PutLargeBuffer returns a large buffer to the pool
func PutLargeBuffer(buf []byte) {
	largeBufferPool.Put(buf)
}

// GetStringSlice retrieves a string slice from the pool
func GetStringSlice() []string {
	return globalStringPool.Get()
}

// PutStringSlice returns a string slice to the pool
func PutStringSlice(slice []string) {
	globalStringPool.Put(slice)
}

// GetIPAllocator retrieves an IP allocator from the pool
func GetIPAllocator() *IPAllocator {
	return globalIPAllocatorPool.Get()
}

// PutIPAllocator returns an IP allocator to the pool
func PutIPAllocator(allocator *IPAllocator) {
	globalIPAllocatorPool.Put(allocator)
}