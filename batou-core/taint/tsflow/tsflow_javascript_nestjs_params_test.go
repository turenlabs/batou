package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// NestJS dependency-injection request surfaces and destructured request-bound
// parameters seed taint. Before seedJSParamBindings these modern idioms bound
// nothing (jsExtractParams only collects plain identifier params), so the
// dominant NestJS controller-action shapes produced ZERO taint.

func TestJS_NestParam_BodyDestructuredToCommand(t *testing.T) {
	code := `
import { Body } from '@nestjs/common';
import { exec } from 'child_process';

class RunController {
  run(@Body() { cmd }: RunDto) {
    exec(cmd);
  }
}
`
	flows := Analyze(code, "/app/run.controller.ts", rules.LangTypeScript)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command flow from @Body() { cmd } -> exec(cmd)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_NestParam_QueryIdentToCommand(t *testing.T) {
	code := `
import { Query } from '@nestjs/common';
import { exec } from 'child_process';

class SearchController {
  search(@Query() q) {
    exec(q);
  }
}
`
	flows := Analyze(code, "/app/search.controller.ts", rules.LangTypeScript)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command flow from @Query() q -> exec(q)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_NestParam_BodyBoundThenAccessed(t *testing.T) {
	code := `
import { Body } from '@nestjs/common';
import { exec } from 'child_process';

class RunController {
  run(@Body() body: RunDto) {
    exec(body.cmd);
  }
}
`
	flows := Analyze(code, "/app/run2.controller.ts", rules.LangTypeScript)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command flow from @Body() body -> exec(body.cmd)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Destructured handler param on an annotated (route-decorated) method seeds the
// bound names. The @Get() decorator marks the action as a request handler.
func TestJS_DestructuredHandlerParam_ToCommand(t *testing.T) {
	code := `
import { Get } from '@nestjs/common';
import { exec } from 'child_process';

class FilesController {
  @Get()
  list(@Query() { dir }) {
    exec('ls ' + dir);
  }
}
`
	flows := Analyze(code, "/app/files.controller.ts", rules.LangTypeScript)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command flow from @Query() { dir } -> exec('ls ' + dir)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative: a NestJS action whose sink uses a CONSTANT command must NOT produce
// a command flow even though @Body() seeds the destructured param. This guards
// against over-tainting (the seeded taint must actually reach the sink).
func TestJS_NestParam_ConstantCommand_NoFlow(t *testing.T) {
	code := `
import { Body } from '@nestjs/common';
import { exec } from 'child_process';

class PingController {
  ping(@Body() { note }: PingDto) {
    exec('echo pong');
  }
}
`
	flows := Analyze(code, "/app/ping.controller.ts", rules.LangTypeScript)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("unexpected command flow: constant command must not be tainted by @Body() seeding")
	}
}

// Field-sensitivity guard: destructuring `{ a }` from a request must NOT taint
// a sibling field `b` that is never bound. Mirrors the multilevel field test
// invariant that a prior change had to respect.
func TestJS_NestParam_SiblingFieldNotTainted(t *testing.T) {
	code := `
import { Body } from '@nestjs/common';
import { exec } from 'child_process';

class C {
  run(@Body() { safe }: Dto) {
    const evil = "constant";
    exec(evil);
  }
}
`
	flows := Analyze(code, "/app/sib.controller.ts", rules.LangTypeScript)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("unexpected command flow: unrelated local must not inherit @Body() taint")
	}
}
