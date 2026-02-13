package massassign

import (
	"regexp"
	"strings"

	"github.com/turen/gtss/internal/rules"
)

// --- Compiled patterns ---

// GTSS-MASS-001: JavaScript/TypeScript mass assignment
var (
	// Object.assign(model, req.body) — direct mass assignment
	jsObjectAssignModel = regexp.MustCompile(`Object\.assign\s*\(\s*(?:user|model|record|entity|account|profile|doc|document|item|obj|instance|data)\w*\s*,\s*(?:req\.body|req\.query|req\.params|request\.body|body|payload|input|data)`)
	// Spread into DB model: {...user, ...req.body} or Object.assign({}, model, req.body)
	jsSpreadIntoModel = regexp.MustCompile(`\{\s*\.\.\.(?:user|model|record|entity|account|profile|doc|document|item)\w*\s*,\s*\.\.\.(?:req\.body|req\.query|req\.params|request\.body|body|payload|input)`)
	// Mongoose/Sequelize update with raw body: Model.update(req.body) / model.set(req.body)
	jsORMUpdateRaw = regexp.MustCompile(`\.\s*(?:update|updateOne|updateMany|findOneAndUpdate|findByIdAndUpdate|set|assign)\s*\(\s*(?:req\.body|req\.query|request\.body|body|payload|input)`)
	// new Model(req.body) — constructor with raw user input
	jsModelConstructor = regexp.MustCompile(`new\s+(?:User|Model|Account|Profile|Record|Entity|Document|Item)\w*\s*\(\s*(?:req\.body|req\.query|request\.body|body|payload|input)`)
)

// GTSS-MASS-002: Python mass assignment
var (
	// Django: Model.objects.create(**request.data) or Model(**request.data)
	pyDjangoCreateUnpack = regexp.MustCompile(`(?:\.objects\.create|\.objects\.update_or_create|\.objects\.get_or_create)\s*\(\s*\*\*\s*(?:request\.data|request\.POST|request\.GET|request\.json|data|payload|input|body)`)
	pyModelUnpack        = regexp.MustCompile(`\b(?:User|Model|Account|Profile|Record|Entity)\w*\s*\(\s*\*\*\s*(?:request\.data|request\.POST|request\.GET|request\.json|data|payload|input|body)`)
	// Flask: Model(**request.json)
	pyFlaskModelUnpack = regexp.MustCompile(`\w+\s*\(\s*\*\*\s*request\.(?:json|form|values|args)`)
	// DRF serializer without explicit fields
	pySerializerNoFields = regexp.MustCompile(`class\s+\w+Serializer\s*\(`)
	pyMetaFieldsAll      = regexp.MustCompile(`fields\s*=\s*['"]__all__['"]`)
	// update with raw dict: instance.__dict__.update(data)
	pyDictUpdate = regexp.MustCompile(`\.__dict__\.update\s*\(\s*(?:request\.data|request\.POST|request\.json|data|payload|input|body)`)
	// setattr loop: for key, val in data.items(): setattr(obj, key, val)
	pySetattrLoop = regexp.MustCompile(`setattr\s*\(\s*\w+\s*,\s*(?:key|k|attr|field|prop)\s*,`)
)

// GTSS-MASS-003: Ruby/Rails mass assignment
var (
	// User.new(params[:user]) without strong params
	rbModelNewParams = regexp.MustCompile(`\.\s*(?:new|create|create!|update|update!|update_attributes|assign_attributes|build)\s*\(\s*params\s*\[\s*:`)
	// params.permit check
	rbStrongParams = regexp.MustCompile(`\.permit\s*\(`)
	// Direct params usage without permit
	rbParamsDirectAssign = regexp.MustCompile(`\.\s*(?:update|update!|assign_attributes)\s*\(\s*params\)`)
)

// GTSS-MASS-004: Java/Spring mass assignment
var (
	// @ModelAttribute without @InitBinder
	javaModelAttribute = regexp.MustCompile(`@ModelAttribute`)
	javaInitBinder     = regexp.MustCompile(`@InitBinder`)
	// BeanUtils.copyProperties with request data
	javaBeanCopy = regexp.MustCompile(`BeanUtils\.copyProperties\s*\(`)
	// Spring Data save with raw binding
	javaRequestBodyDirect = regexp.MustCompile(`@RequestBody\s+\w+\s+\w+`)
)

func init() {
	rules.Register(&MassAssignJS{})
	rules.Register(&MassAssignPython{})
	rules.Register(&MassAssignRuby{})
	rules.Register(&MassAssignJava{})
}

// --- GTSS-MASS-001: JavaScript Mass Assignment ---

type MassAssignJS struct{}

func (r *MassAssignJS) ID() string                        { return "GTSS-MASS-001" }
func (r *MassAssignJS) Name() string                      { return "MassAssignJS" }
func (r *MassAssignJS) DefaultSeverity() rules.Severity   { return rules.High }
func (r *MassAssignJS) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *MassAssignJS) Description() string {
	return "Detects mass assignment vulnerabilities in JavaScript/TypeScript where user input is directly merged into data models."
}

func (r *MassAssignJS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if isComment(trimmed) {
			continue
		}

		var matched string
		var confidence string
		var title string

		if loc := jsObjectAssignModel.FindString(line); loc != "" {
			matched = loc
			confidence = "high"
			title = "Mass assignment via Object.assign with user input into model"
		}

		if matched == "" {
			if loc := jsSpreadIntoModel.FindString(line); loc != "" {
				matched = loc
				confidence = "medium"
				title = "Mass assignment via spread operator with user input into model"
			}
		}

		if matched == "" {
			if loc := jsORMUpdateRaw.FindString(line); loc != "" {
				matched = loc
				confidence = "high"
				title = "ORM update with raw user input (mass assignment)"
			}
		}

		if matched == "" {
			if loc := jsModelConstructor.FindString(line); loc != "" {
				matched = loc
				confidence = "medium"
				title = "Model constructor with raw user input (mass assignment)"
			}
		}

		if matched != "" {
			if hasFieldWhitelist(lines, i) {
				continue
			}

			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   "User-controlled input is directly assigned to a data model without field filtering. An attacker could set unauthorized fields like isAdmin, role, or password to escalate privileges.",
				FilePath:      ctx.FilePath,
				LineNumber:    lineNum,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Explicitly pick only allowed fields from user input before assigning to models. Use a whitelist pattern: const { name, email } = req.body; instead of passing the entire body.",
				CWEID:         "CWE-915",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"mass-assignment", "user-input", "orm"},
			})
		}
	}

	return findings
}

// --- GTSS-MASS-002: Python Mass Assignment ---

type MassAssignPython struct{}

func (r *MassAssignPython) ID() string                        { return "GTSS-MASS-002" }
func (r *MassAssignPython) Name() string                      { return "MassAssignPython" }
func (r *MassAssignPython) DefaultSeverity() rules.Severity   { return rules.High }
func (r *MassAssignPython) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *MassAssignPython) Description() string {
	return "Detects mass assignment vulnerabilities in Python where user input is unpacked into ORM models."
}

func (r *MassAssignPython) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check for DRF serializer with fields = '__all__'
	hasSerializerClass := pySerializerNoFields.MatchString(ctx.Content)
	hasFieldsAll := pyMetaFieldsAll.MatchString(ctx.Content)

	if hasSerializerClass && hasFieldsAll {
		for i, line := range lines {
			if pyMetaFieldsAll.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      rules.Medium,
					SeverityLabel: rules.Medium.String(),
					Title:         "DRF serializer with fields = '__all__' (mass assignment risk)",
					Description:   "A Django REST Framework serializer exposes all model fields. This may allow users to set sensitive fields like is_staff, is_superuser, or password.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Explicitly list allowed fields instead of using '__all__'. Use read_only_fields for sensitive attributes.",
					CWEID:         "CWE-915",
					OWASPCategory: "A04:2021-Insecure Design",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"mass-assignment", "django", "drf", "serializer"},
				})
			}
		}
	}

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if isComment(trimmed) {
			continue
		}

		var matched string
		var confidence string
		var title string

		if loc := pyDjangoCreateUnpack.FindString(line); loc != "" {
			matched = loc
			confidence = "high"
			title = "Django ORM create/update with unpacked user input"
		}

		if matched == "" {
			if loc := pyModelUnpack.FindString(line); loc != "" {
				matched = loc
				confidence = "medium"
				title = "Model instantiation with unpacked user input"
			}
		}

		if matched == "" {
			if loc := pyFlaskModelUnpack.FindString(line); loc != "" {
				matched = loc
				confidence = "medium"
				title = "Model instantiation with unpacked request data"
			}
		}

		if matched == "" {
			if loc := pyDictUpdate.FindString(line); loc != "" {
				matched = loc
				confidence = "high"
				title = "Direct __dict__.update with user input (mass assignment)"
			}
		}

		if matched == "" {
			if loc := pySetattrLoop.FindString(line); loc != "" {
				// Check if it is in a loop context
				if isInLoop(lines, i) {
					matched = loc
					confidence = "medium"
					title = "setattr loop with dynamic keys (mass assignment risk)"
				}
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   "User input is unpacked directly into a model or ORM call. An attacker could inject unexpected fields to escalate privileges or modify sensitive attributes.",
				FilePath:      ctx.FilePath,
				LineNumber:    lineNum,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Explicitly select allowed fields before passing to models. Use Django forms or DRF serializers with explicit field lists. Never use **request.data directly.",
				CWEID:         "CWE-915",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"mass-assignment", "python", "orm"},
			})
		}
	}

	return findings
}

// --- GTSS-MASS-003: Ruby Mass Assignment ---

type MassAssignRuby struct{}

func (r *MassAssignRuby) ID() string                        { return "GTSS-MASS-003" }
func (r *MassAssignRuby) Name() string                      { return "MassAssignRuby" }
func (r *MassAssignRuby) DefaultSeverity() rules.Severity   { return rules.High }
func (r *MassAssignRuby) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *MassAssignRuby) Description() string {
	return "Detects mass assignment in Ruby/Rails where params are used without strong parameters (permit)."
}

func (r *MassAssignRuby) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Pre-check: does the file use strong params (.permit)?
	hasStrongParams := rbStrongParams.MatchString(ctx.Content)

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if isComment(trimmed) {
			continue
		}

		var matched string
		var confidence string
		var title string

		// Direct params assignment without permit
		if loc := rbParamsDirectAssign.FindString(line); loc != "" {
			matched = loc
			confidence = "high"
			title = "Mass assignment with raw params (no strong parameters)"
		}

		// Model.new/create(params[:user]) — check if strong params are used elsewhere
		if matched == "" {
			if loc := rbModelNewParams.FindString(line); loc != "" {
				if !hasStrongParams {
					matched = loc
					confidence = "high"
					title = "Mass assignment with params without strong parameters"
				} else {
					// File has .permit somewhere — lower confidence, might be OK
					matched = loc
					confidence = "low"
					title = "Model creation with params (verify strong parameters are applied)"
				}
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   "Rails params are passed directly to a model without strong parameters (permit). An attacker could set any model attribute, including admin flags and associations.",
				FilePath:      ctx.FilePath,
				LineNumber:    lineNum,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use strong parameters: params.require(:user).permit(:name, :email). Never pass raw params directly to model methods.",
				CWEID:         "CWE-915",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"mass-assignment", "rails", "strong-params"},
			})
		}
	}

	return findings
}

// --- GTSS-MASS-004: Java Mass Assignment ---

type MassAssignJava struct{}

func (r *MassAssignJava) ID() string                        { return "GTSS-MASS-004" }
func (r *MassAssignJava) Name() string                      { return "MassAssignJava" }
func (r *MassAssignJava) DefaultSeverity() rules.Severity   { return rules.High }
func (r *MassAssignJava) Languages() []rules.Language {
	return []rules.Language{rules.LangJava}
}

func (r *MassAssignJava) Description() string {
	return "Detects mass assignment in Java/Spring where HTTP request data is bound directly to domain objects without field restrictions."
}

func (r *MassAssignJava) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Pre-check: does the file have @InitBinder?
	hasInitBinder := javaInitBinder.MatchString(ctx.Content)

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if isComment(trimmed) {
			continue
		}

		// @ModelAttribute without @InitBinder
		if javaModelAttribute.MatchString(line) {
			if !hasInitBinder {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "@ModelAttribute without @InitBinder field restriction",
					Description:   "Spring @ModelAttribute binds all HTTP request parameters to the model object. Without @InitBinder to restrict allowed fields, an attacker can set any model property.",
					FilePath:      ctx.FilePath,
					LineNumber:    lineNum,
					MatchedText:   truncate(trimmed, 120),
					Suggestion:    "Add an @InitBinder method that calls binder.setAllowedFields() to whitelist bindable properties, or use a DTO with only the fields you want to accept.",
					CWEID:         "CWE-915",
					OWASPCategory: "A04:2021-Insecure Design",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"mass-assignment", "spring", "model-binding"},
				})
			}
		}

		// BeanUtils.copyProperties
		if javaBeanCopy.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Medium,
				SeverityLabel: rules.Medium.String(),
				Title:         "BeanUtils.copyProperties may enable mass assignment",
				Description:   "BeanUtils.copyProperties copies all matching properties between objects. If the source is user-controlled, unexpected fields may be set on the target.",
				FilePath:      ctx.FilePath,
				LineNumber:    lineNum,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Use a DTO pattern with explicit field mapping instead of BeanUtils.copyProperties. Or use the overload that accepts an ignore list for sensitive fields.",
				CWEID:         "CWE-915",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"mass-assignment", "java", "bean-copy"},
			})
		}
	}

	return findings
}

// --- Helpers ---

func hasFieldWhitelist(lines []string, idx int) bool {
	start := idx - 5
	if start < 0 {
		start = 0
	}
	end := idx + 3
	if end > len(lines) {
		end = len(lines)
	}

	for _, l := range lines[start:end] {
		lower := strings.ToLower(l)
		if strings.Contains(lower, "allowedfields") || strings.Contains(lower, "allowed_fields") ||
			strings.Contains(lower, "whitelist") || strings.Contains(lower, "allowlist") ||
			strings.Contains(lower, "pick(") || strings.Contains(lower, "_.pick") ||
			strings.Contains(lower, "sanitize") || strings.Contains(lower, "filterfields") ||
			strings.Contains(lower, "filter_fields") {
			return true
		}
	}
	return false
}

func isInLoop(lines []string, idx int) bool {
	start := idx - 3
	if start < 0 {
		start = 0
	}
	for _, l := range lines[start : idx+1] {
		lower := strings.ToLower(l)
		if strings.Contains(lower, "for ") || strings.Contains(lower, "for(") ||
			strings.Contains(lower, ".items()") || strings.Contains(lower, ".each") {
			return true
		}
	}
	return false
}

func isComment(line string) bool {
	return strings.HasPrefix(line, "//") ||
		strings.HasPrefix(line, "#") ||
		strings.HasPrefix(line, "*") ||
		strings.HasPrefix(line, "/*") ||
		strings.HasPrefix(line, "<!--")
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
