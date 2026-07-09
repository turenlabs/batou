package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Perl — additional Redis.pm read commands as second-order taint sources.
//
// Perl previously modeled only get/mget/hgetall/blpop/subscribe as sources.
// Hash-field, list, set, and sorted-set read methods were missing, so values
// previously stored by an untrusted user (cache poisoning, queue contents)
// were not flagged when later concatenated into a sink.
//
// Mirrors lua.resty.redis.* (PR #505), go.redis.* (PR #647), java.jedis.*
// (PR #641), and the in-flight phpredis / ioredis / redis-rb / redis-py /
// StackExchange.Redis / RediStack / redis-rs PRs.
//
// Kept in a dedicated file to avoid the tsflow_test.go merge bottleneck.
// =========================================================================

// Hash field read — second-order command injection.
func TestPerl_Redis_HGet_SecondOrder_Command(t *testing.T) {
	code := `
use Redis;
sub handler {
    my $redis = Redis->new;
    my $val = $redis->hget("settings", "binary");
    return system("/usr/bin/run " . $val);
}
`
	flows := Analyze(code, "/app/r.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $redis->hget -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPerl_Redis_HKeys_SecondOrder_Command(t *testing.T) {
	code := `
use Redis;
sub handler {
    my $redis = Redis->new;
    my $key = $redis->hkeys("config");
    return system("echo " . $key);
}
`
	flows := Analyze(code, "/app/r.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $redis->hkeys -> system")
	}
}

func TestPerl_Redis_HVals_SecondOrder_Command(t *testing.T) {
	code := `
use Redis;
sub handler {
    my $redis = Redis->new;
    my $v = $redis->hvals("config");
    return system("echo " . $v);
}
`
	flows := Analyze(code, "/app/r.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $redis->hvals -> system")
	}
}

func TestPerl_Redis_HMGet_SecondOrder_Command(t *testing.T) {
	code := `
use Redis;
sub handler {
    my $redis = Redis->new;
    my $v = $redis->hmget("settings", "a", "b");
    return system("echo " . $v);
}
`
	flows := Analyze(code, "/app/r.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $redis->hmget -> system")
	}
}

// List read — second-order command injection.
func TestPerl_Redis_LRange_SecondOrder_Command(t *testing.T) {
	code := `
use Redis;
sub handler {
    my $redis = Redis->new;
    my $v = $redis->lrange("queue", 0, -1);
    return system("echo " . $v);
}
`
	flows := Analyze(code, "/app/r.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $redis->lrange -> system")
	}
}

func TestPerl_Redis_LPop_SecondOrder_Command(t *testing.T) {
	code := `
use Redis;
sub handler {
    my $redis = Redis->new;
    my $v = $redis->lpop("queue");
    return system("echo " . $v);
}
`
	flows := Analyze(code, "/app/r.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $redis->lpop -> system")
	}
}

func TestPerl_Redis_RPop_SecondOrder_Command(t *testing.T) {
	code := `
use Redis;
sub handler {
    my $redis = Redis->new;
    my $v = $redis->rpop("queue");
    return system("echo " . $v);
}
`
	flows := Analyze(code, "/app/r.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $redis->rpop -> system")
	}
}

func TestPerl_Redis_LIndex_SecondOrder_Command(t *testing.T) {
	code := `
use Redis;
sub handler {
    my $redis = Redis->new;
    my $v = $redis->lindex("queue", 0);
    return system("echo " . $v);
}
`
	flows := Analyze(code, "/app/r.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $redis->lindex -> system")
	}
}

// Set read — second-order command injection.
func TestPerl_Redis_SMembers_SecondOrder_Command(t *testing.T) {
	code := `
use Redis;
sub handler {
    my $redis = Redis->new;
    my $v = $redis->smembers("allowed");
    return system("echo " . $v);
}
`
	flows := Analyze(code, "/app/r.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $redis->smembers -> system")
	}
}

func TestPerl_Redis_SRandMember_SecondOrder_Command(t *testing.T) {
	code := `
use Redis;
sub handler {
    my $redis = Redis->new;
    my $v = $redis->srandmember("pool");
    return system("echo " . $v);
}
`
	flows := Analyze(code, "/app/r.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $redis->srandmember -> system")
	}
}

func TestPerl_Redis_SPop_SecondOrder_Command(t *testing.T) {
	code := `
use Redis;
sub handler {
    my $redis = Redis->new;
    my $v = $redis->spop("pool");
    return system("echo " . $v);
}
`
	flows := Analyze(code, "/app/r.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $redis->spop -> system")
	}
}

// Sorted set read — second-order command injection.
func TestPerl_Redis_ZRange_SecondOrder_Command(t *testing.T) {
	code := `
use Redis;
sub handler {
    my $redis = Redis->new;
    my $v = $redis->zrange("leaderboard", 0, -1);
    return system("echo " . $v);
}
`
	flows := Analyze(code, "/app/r.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $redis->zrange -> system")
	}
}

func TestPerl_Redis_ZRevRange_SecondOrder_Command(t *testing.T) {
	code := `
use Redis;
sub handler {
    my $redis = Redis->new;
    my $v = $redis->zrevrange("leaderboard", 0, -1);
    return system("echo " . $v);
}
`
	flows := Analyze(code, "/app/r.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $redis->zrevrange -> system")
	}
}

func TestPerl_Redis_ZRangeByScore_SecondOrder_Command(t *testing.T) {
	code := `
use Redis;
sub handler {
    my $redis = Redis->new;
    my $v = $redis->zrangebyscore("leaderboard", 0, 100);
    return system("echo " . $v);
}
`
	flows := Analyze(code, "/app/r.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $redis->zrangebyscore -> system")
	}
}

// Negative — a constant string passed to system() must NOT trigger a flow,
// otherwise the entries are over-broad (firing on any string concat into
// system, regardless of whether Redis was actually involved).
func TestPerl_Redis_ConstantCommand_NoFlow(t *testing.T) {
	code := `
sub handler {
    return system("echo " . "literal");
}
`
	flows := Analyze(code, "/app/r.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			t.Errorf("unexpected SnkCommand flow on constant input: %s -> %s",
				f.Source.Category, f.Sink.Category)
		}
	}
}
