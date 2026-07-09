package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// --- Trust boundary violation tests (CWE-501) ---
//
// These exercise the Java SnkTrustBoundary sinks added for servlet request
// scope, JSP PageContext, and Spring MVC model / redirect attributes.

func TestJava_TrustBoundary_HttpServletRequestSetAttribute(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler {
    public void handle(HttpServletRequest request, HttpServletResponse response) {
        String user = request.getParameter("username");
        request.setAttribute("displayUser", user);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow: request.getParameter -> request.setAttribute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_TrustBoundary_PageContextSetAttribute(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.servlet.jsp.*;

public class JspHelper {
    public void store(HttpServletRequest request, PageContext pageContext) {
        String msg = request.getParameter("msg");
        pageContext.setAttribute("greeting", msg);
    }
}
`
	flows := Analyze(code, "/app/JspHelper.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow: request.getParameter -> pageContext.setAttribute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_TrustBoundary_SpringModelAddAttribute(t *testing.T) {
	code := `
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class Greeter {
    @GetMapping("/hello")
    public String hello(@RequestParam String name, Model model) {
        model.addAttribute("name", name);
        return "hello";
    }
}
`
	flows := Analyze(code, "/app/Greeter.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow: @RequestParam -> model.addAttribute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_TrustBoundary_SpringModelMapAddAttribute(t *testing.T) {
	code := `
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.*;

@Controller
public class Profile {
    @GetMapping("/profile")
    public String show(@RequestParam String id, ModelMap modelMap) {
        modelMap.addAttribute("userId", id);
        return "profile";
    }
}
`
	flows := Analyze(code, "/app/Profile.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow: @RequestParam -> modelMap.addAttribute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_TrustBoundary_SpringModelAndViewAddObject(t *testing.T) {
	code := `
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class Dashboard {
    @GetMapping("/dash")
    public ModelAndView view(@RequestParam String title) {
        ModelAndView modelAndView = new ModelAndView("dashboard");
        modelAndView.addObject("title", title);
        return modelAndView;
    }
}
`
	flows := Analyze(code, "/app/Dashboard.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow: @RequestParam -> modelAndView.addObject")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_TrustBoundary_SpringRedirectAttributesAddFlashAttribute(t *testing.T) {
	code := `
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class Flow {
    @PostMapping("/submit")
    public String submit(@RequestParam String note, RedirectAttributes redirectAttributes) {
        redirectAttributes.addFlashAttribute("notice", note);
        return "redirect:/done";
    }
}
`
	flows := Analyze(code, "/app/Flow.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow: @RequestParam -> redirectAttributes.addFlashAttribute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_TrustBoundary_SpringRedirectAttributesAddAttribute(t *testing.T) {
	code := `
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class Search {
    @GetMapping("/search")
    public String search(@RequestParam String q, RedirectAttributes redirectAttributes) {
        redirectAttributes.addAttribute("q", q);
        return "redirect:/results";
    }
}
`
	flows := Analyze(code, "/app/Search.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow: @RequestParam -> redirectAttributes.addAttribute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
