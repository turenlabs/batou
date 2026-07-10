package race

import (
	"testing"

	"github.com/turenlabs/batou-rules/testutil"
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

// --- BATOU-RACE-003: Balance/counter race (FP gates from owncloud/web) ---

func TestRACE003_Go_GoroutineCounter_Fires(t *testing.T) {
	content := `package bank
func process() {
	for i := 0; i < 10; i++ {
		go func() {
			balance = balance + amount
		}()
	}
}`
	result := testutil.ScanContent(t, "/app/bank.go", content)
	testutil.MustFindRule(t, result, "BATOU-RACE-003")
}

func TestRACE003_Java_Counter_Fires(t *testing.T) {
	content := `public class Wallet {
    private int balance;
    void withdraw(int amount) {
        balance -= amount;
    }
}`
	result := testutil.ScanContent(t, "/app/Wallet.java", content)
	testutil.MustFindRule(t, result, "BATOU-RACE-003")
}

func TestRACE003_Node_ServerSide_Fires(t *testing.T) {
	// Server-side JS: concurrent HTTP requests can race the same DB row.
	content := `const express = require('express');
const app = express();
app.post('/withdraw', async (req, res) => {
  let balance = await db.getBalance(req.body.user);
  balance = balance - req.body.amount;
  await db.setBalance(req.body.user, balance);
  res.json({ balance });
});`
	result := testutil.ScanContent(t, "/app/wallet.js", content)
	testutil.MustFindRule(t, result, "BATOU-RACE-003")
}

func TestRACE003_Node_WorkerThreads_Fires(t *testing.T) {
	content := `const { Worker } = require('worker_threads');
const buf = new SharedArrayBuffer(8);
let sharedCount = 0;
function tick() { sharedCount += 1; }`
	result := testutil.ScanContent(t, "/app/worker.js", content)
	testutil.MustFindRule(t, result, "BATOU-RACE-003")
}

func TestRACE003_Safe_FrontendUploadCounter(t *testing.T) {
	// Frontend upload-progress UI counter — single-threaded, no race.
	content := `export function useUpload() {
  const filesCount = ref(0)
  const successCount = ref(0)
  function onFileDone(ok: boolean) {
    if (ok) {
      successCount.value += 1
    }
    filesCount.value += 1
  }
  return { filesCount, successCount, onFileDone }
}`
	result := testutil.ScanContent(t, "/app/composables/useUpload.ts", content)
	testutil.MustNotFindRule(t, result, "BATOU-RACE-003")
}

func TestRACE003_Safe_VueComponentCounter(t *testing.T) {
	content := `<script setup lang="ts">
import { ref } from 'vue'
const runningUploads = ref(0)
function startUpload() {
  runningUploads.value += 1
}
</script>`
	result := testutil.ScanContent(t, "/app/components/UploadBar.vue", content)
	testutil.MustNotFindRule(t, result, "BATOU-RACE-003")
}
