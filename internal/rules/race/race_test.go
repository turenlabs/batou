package race

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// --- BATOU-RACE-002: Check-then-act without locking ---

func TestRACE002_Python_Asyncio_NoTrigger(t *testing.T) {
	content := `import asyncio

cache = {}

async def handler(key):
    if cache.get(key):
        return cache[key]
    value = await fetch(key)
    cache[key] = value
    return value
`
	result := testutil.ScanContent(t, "/app/handler.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-RACE-002")
}

func TestRACE002_Python_NoAsyncio_Triggers(t *testing.T) {
	content := `import threading

shared = {}

def worker(key, value):
    if shared.get(key):
        return shared[key]
    shared[key] = value
`
	result := testutil.ScanContent(t, "/app/worker.py", content)
	testutil.MustFindRule(t, result, "BATOU-RACE-002")
}

func TestRACE002_Go_WithGoroutine_Triggers(t *testing.T) {
	content := `package main

func process(m map[string]int, key string) {
    go func() {
        doWork()
    }()
    if m[key] == 0 {
        m[key] = 1
    }
}
`
	result := testutil.ScanContent(t, "/app/process.go", content)
	testutil.MustFindRule(t, result, "BATOU-RACE-002")
}

func TestRACE002_Go_WithLock_Safe(t *testing.T) {
	content := `package main

import "sync"

var mu sync.Mutex

func process(m map[string]int, key string) {
    go func() {
        doWork()
    }()
    mu.Lock()
    if m[key] == 0 {
        m[key] = 1
    }
    mu.Unlock()
}
`
	result := testutil.ScanContent(t, "/app/process.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-RACE-002")
}
