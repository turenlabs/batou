package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func anyEvalFlow(flows []taint.TaintFlow) bool {
	for _, f := range flows {
		if f.Sink.ID == "ruby.public_send" || f.Sink.ID == "ruby.send" {
			return true
		}
	}
	return false
}

// TestRuby_CaseAllLiteralArms_Suppressed is the load-bearing test for the
// class-C over-taint fix (discourse group.rb:517). A variable assigned by a
// `case`/`when` whose every arm is a fixed literal string is a validated
// allowlist enum — it must NOT inherit the DB-tainted case subject.
func TestRuby_CaseAllLiteralArms_Suppressed(t *testing.T) {
	// FP shape: `action` is only ever "track!"/"regular!"/"mute!"/"track!".
	// The subject `notification_level` comes from a DB pluck (tainted) but the
	// case maps it to a fixed literal set, so public_send(action) is safe.
	fp := `def notify(group_users, topic)
  group_users.pluck(:user_id, :notification_level).each do |user_id, notification_level|
    action =
      case notification_level
      when 1
        "track!"
      when 2
        "regular!"
      when 3
        "mute!"
      else
        "track!"
      end
    topic.notifier.public_send(action, user_id)
  end
end
`
	flows := Analyze(fp, "/app/group.rb", rules.LangRuby)
	if anyEvalFlow(flows) {
		t.Errorf("class-C FP: all-literal case/when must not taint public_send arg; got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow sink=%s cwe=%s", f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// TestRuby_CaseTaintedArm_StillFires is the negative-control: if ANY arm yields
// a tainted (non-literal) value, the discriminator must NOT suppress — the
// enum-mapping guarantee no longer holds.
func TestRuby_CaseTaintedArm_StillFires(t *testing.T) {
	// One arm returns the tainted subject directly → action can equal
	// notification_level → public_send is genuinely attacker-influenced.
	vuln := `def notify(group_users, topic)
  group_users.pluck(:user_id, :notification_level).each do |user_id, notification_level|
    action =
      case notification_level
      when 1
        "track!"
      else
        notification_level
      end
    topic.notifier.public_send(action, user_id)
  end
end
`
	flows := Analyze(vuln, "/app/group.rb", rules.LangRuby)
	if !anyEvalFlow(flows) {
		t.Errorf("class-C control: a tainted case arm must still reach public_send; got 0 eval flows (%d total)", len(flows))
	}
}

// TestRuby_CaseInterpolatedArm_StillFires: an interpolated string arm embeds an
// arbitrary expression and must not be treated as a safe literal.
func TestRuby_CaseInterpolatedArm_StillFires(t *testing.T) {
	vuln := `def notify(group_users, topic)
  group_users.pluck(:user_id, :notification_level).each do |user_id, notification_level|
    action =
      case notification_level
      when 1
        "track!"
      else
        "do_#{notification_level}!"
      end
    topic.notifier.public_send(action, user_id)
  end
end
`
	flows := Analyze(vuln, "/app/group.rb", rules.LangRuby)
	if !anyEvalFlow(flows) {
		t.Errorf("class-C control: an interpolated case arm must still reach public_send; got 0 eval flows (%d total)", len(flows))
	}
}

// TestRuby_CaseSymbolArms_Suppressed: symbol arms (common Rails enum form) are
// also fixed literals and should be suppressed.
func TestRuby_CaseSymbolArms_Suppressed(t *testing.T) {
	fp := `def dispatch(model, topic)
  model.pluck(:level).each do |level|
    action =
      case level
      when 1
        :track
      when 2
        :mute
      else
        :track
      end
    topic.notifier.public_send(action)
  end
end
`
	flows := Analyze(fp, "/app/dispatch.rb", rules.LangRuby)
	if anyEvalFlow(flows) {
		t.Errorf("class-C FP: all-symbol case/when must not taint public_send arg; got %d flows", len(flows))
	}
}
