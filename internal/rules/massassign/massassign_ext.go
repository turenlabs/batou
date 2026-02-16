package massassign

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for extended mass assignment rules
// ---------------------------------------------------------------------------

// GTSS-MASS-005: Django model form without Meta.fields
var (
	reDjangoModelForm     = regexp.MustCompile(`class\s+\w+\s*\(\s*(?:forms\.ModelForm|ModelForm)\s*\)`)
	reDjangoMetaFields    = regexp.MustCompile(`(?:fields\s*=|exclude\s*=)`)
	reDjangoFieldsAll     = regexp.MustCompile(`fields\s*=\s*['"]__all__['"]`)
	reDjangoExcludeEmpty  = regexp.MustCompile(`exclude\s*=\s*(?:\[\s*\]|\(\s*\))`)
)

// GTSS-MASS-006: Spring @ModelAttribute without @InitBinder
var (
	reSpringModelAttr    = regexp.MustCompile(`@ModelAttribute\b`)
	reSpringInitBinder   = regexp.MustCompile(`@InitBinder\b`)
	reSpringAllowedFields = regexp.MustCompile(`setAllowedFields\b`)
	reSpringDisallowed   = regexp.MustCompile(`setDisallowedFields\b`)
)

// GTSS-MASS-007: Express body parsed directly into DB query
var (
	reExpressBodyToDB = regexp.MustCompile(`(?:\.create|\.insert|\.insertMany|\.save|\.update|\.updateOne|\.updateMany|\.findOneAndUpdate|\.findByIdAndUpdate|\.replaceOne)\s*\(\s*(?:req\.body|request\.body)\s*\)`)
	reExpressSpreadDB = regexp.MustCompile(`(?:\.create|\.insert|\.save|\.update)\s*\(\s*\{\s*\.\.\.req\.body\s*\}`)
)

// GTSS-MASS-008: ASP.NET model binding without [Bind]
var (
	reAspNetAction      = regexp.MustCompile(`(?:public\s+(?:async\s+)?(?:IActionResult|ActionResult|Task<IActionResult>|Task<ActionResult>)\s+\w+\s*\([^)]*\w+\s+\w+\s*\))`)
	reAspNetBind        = regexp.MustCompile(`\[Bind\b`)
	reAspNetBindNever   = regexp.MustCompile(`\[BindNever\b`)
	reAspNetFromBody    = regexp.MustCompile(`\[FromBody\b`)
)

// GTSS-MASS-009: Go struct binding from JSON without field tags
var (
	reGoJSONBind      = regexp.MustCompile(`(?:json\.NewDecoder|json\.Unmarshal|\.ShouldBindJSON|\.BindJSON|\.Decode)\s*\(`)
	reGoStructDef     = regexp.MustCompile(`type\s+\w+\s+struct\s*\{`)
	reGoJSONTag       = regexp.MustCompile(`json:"[^"]*"`)
	reGoJSONDash      = regexp.MustCompile(`json:"-"`)
)

// GTSS-MASS-010: PHP Eloquent $guarded empty array
var (
	rePHPGuardedEmpty = regexp.MustCompile(`\$guarded\s*=\s*\[\s*\]`)
	rePHPFillable     = regexp.MustCompile(`\$fillable\s*=`)
)

// ---------------------------------------------------------------------------
// GTSS-MASS-005: Django Model Form Without Meta.fields
// ---------------------------------------------------------------------------

type DjangoModelFormNoFields struct{}

func (r *DjangoModelFormNoFields) ID() string                     { return "GTSS-MASS-005" }
func (r *DjangoModelFormNoFields) Name() string                   { return "DjangoModelFormNoFields" }
func (r *DjangoModelFormNoFields) DefaultSeverity() rules.Severity { return rules.High }
func (r *DjangoModelFormNoFields) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}
func (r *DjangoModelFormNoFields) Description() string {
	return "Detects Django ModelForm classes that use fields='__all__' or exclude=[], exposing all model fields to user input."
}

func (r *DjangoModelFormNoFields) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		if reDjangoModelForm.MatchString(line) {
			// Check the next 15 lines for Meta class with fields
			end := i + 15
			if end > len(lines) {
				end = len(lines)
			}
			hasFieldsAll := false
			hasExcludeEmpty := false
			fieldsLine := 0
			fieldsMatch := ""
			for j := i; j < end; j++ {
				if reDjangoFieldsAll.MatchString(lines[j]) {
					hasFieldsAll = true
					fieldsLine = j + 1
					fieldsMatch = strings.TrimSpace(lines[j])
				}
				if reDjangoExcludeEmpty.MatchString(lines[j]) {
					hasExcludeEmpty = true
					fieldsLine = j + 1
					fieldsMatch = strings.TrimSpace(lines[j])
				}
			}
			if hasFieldsAll || hasExcludeEmpty {
				if len(fieldsMatch) > 120 {
					fieldsMatch = fieldsMatch[:120] + "..."
				}
				desc := "fields='__all__' exposes all model fields"
				if hasExcludeEmpty {
					desc = "exclude=[] exposes all model fields"
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Django ModelForm " + desc,
					Description:   "Django ModelForm exposes all model fields to user input. Attackers can set sensitive fields like is_staff, is_superuser, or foreign keys to escalate privileges or corrupt data.",
					FilePath:      ctx.FilePath,
					LineNumber:    fieldsLine,
					MatchedText:   fieldsMatch,
					Suggestion:    "Explicitly list allowed fields: fields = ['name', 'email']. Never use fields='__all__' or exclude=[]. Use read_only_fields for sensitive attributes.",
					CWEID:         "CWE-915",
					OWASPCategory: "A04:2021-Insecure Design",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"mass-assignment", "django", "model-form", "cwe-915"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-MASS-006: Spring @ModelAttribute Without @InitBinder
// ---------------------------------------------------------------------------

type SpringModelAttrNoInitBinder struct{}

func (r *SpringModelAttrNoInitBinder) ID() string                     { return "GTSS-MASS-006" }
func (r *SpringModelAttrNoInitBinder) Name() string                   { return "SpringModelAttrNoInitBinder" }
func (r *SpringModelAttrNoInitBinder) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *SpringModelAttrNoInitBinder) Languages() []rules.Language {
	return []rules.Language{rules.LangJava}
}
func (r *SpringModelAttrNoInitBinder) Description() string {
	return "Detects Spring @ModelAttribute usage without @InitBinder to restrict bindable fields, enabling mass assignment."
}

func (r *SpringModelAttrNoInitBinder) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	if !reSpringModelAttr.MatchString(ctx.Content) {
		return nil
	}
	if reSpringInitBinder.MatchString(ctx.Content) && (reSpringAllowedFields.MatchString(ctx.Content) || reSpringDisallowed.MatchString(ctx.Content)) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		if reSpringModelAttr.MatchString(line) {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "@ModelAttribute without @InitBinder field whitelist",
				Description:   "Spring @ModelAttribute binds all request parameters to the model object. Without an @InitBinder method that calls setAllowedFields() or setDisallowedFields(), an attacker can set any property on the model object.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add @InitBinder with binder.setAllowedFields('name', 'email') to restrict bindable fields. Alternatively, use a DTO/command object with only the fields you want to accept.",
				CWEID:         "CWE-915",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"mass-assignment", "spring", "model-binding", "cwe-915"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-MASS-007: Express Body Parsed Directly Into DB Query
// ---------------------------------------------------------------------------

type ExpressBodyToDB struct{}

func (r *ExpressBodyToDB) ID() string                     { return "GTSS-MASS-007" }
func (r *ExpressBodyToDB) Name() string                   { return "ExpressBodyToDB" }
func (r *ExpressBodyToDB) DefaultSeverity() rules.Severity { return rules.High }
func (r *ExpressBodyToDB) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *ExpressBodyToDB) Description() string {
	return "Detects Express.js request body passed directly to database operations without field filtering, enabling mass assignment."
}

func (r *ExpressBodyToDB) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		matched := ""
		if loc := reExpressBodyToDB.FindString(line); loc != "" {
			matched = loc
		} else if loc := reExpressSpreadDB.FindString(line); loc != "" {
			matched = loc
		}
		if matched != "" {
			if hasFieldWhitelist(lines, i) {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Express req.body passed directly to database operation (mass assignment)",
				Description:   "The full req.body object is passed directly to a database create/update operation. An attacker can include unexpected fields (isAdmin, role, price, userId) in the request body to modify data they should not have access to.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Destructure only the allowed fields from req.body before passing to the database: const { name, email } = req.body; await Model.create({ name, email }). Use a validation library (joi, zod) to define the expected shape.",
				CWEID:         "CWE-915",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"mass-assignment", "express", "mongodb", "cwe-915"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-MASS-008: ASP.NET Model Binding Without [Bind]
// ---------------------------------------------------------------------------

type AspNetModelBindingNoBind struct{}

func (r *AspNetModelBindingNoBind) ID() string                     { return "GTSS-MASS-008" }
func (r *AspNetModelBindingNoBind) Name() string                   { return "AspNetModelBindingNoBind" }
func (r *AspNetModelBindingNoBind) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *AspNetModelBindingNoBind) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}
func (r *AspNetModelBindingNoBind) Description() string {
	return "Detects ASP.NET controller actions that accept model parameters without [Bind] attribute to restrict bindable properties."
}

func (r *AspNetModelBindingNoBind) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Skip if [Bind] or [BindNever] is used in the file
	if reAspNetBind.MatchString(ctx.Content) || reAspNetBindNever.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		if reAspNetAction.MatchString(line) && !reAspNetFromBody.MatchString(line) {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "ASP.NET action method without [Bind] attribute",
				Description:   "An ASP.NET controller action accepts a model parameter without the [Bind] attribute to restrict bindable properties. This allows overposting attacks where users can set properties they should not have access to.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use [Bind(Include = 'Name,Email')] to whitelist bindable properties. Or use a ViewModel/DTO that only contains the properties the user should be able to set. Apply [BindNever] to sensitive properties.",
				CWEID:         "CWE-915",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"mass-assignment", "aspnet", "model-binding", "cwe-915"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-MASS-009: Go Struct Binding Without Field Tags
// ---------------------------------------------------------------------------

type GoStructBindNoTags struct{}

func (r *GoStructBindNoTags) ID() string                     { return "GTSS-MASS-009" }
func (r *GoStructBindNoTags) Name() string                   { return "GoStructBindNoTags" }
func (r *GoStructBindNoTags) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *GoStructBindNoTags) Languages() []rules.Language {
	return []rules.Language{rules.LangGo}
}
func (r *GoStructBindNoTags) Description() string {
	return "Detects Go struct JSON binding where the struct lacks json:\"-\" tags to exclude sensitive fields from binding."
}

func (r *GoStructBindNoTags) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only flag if the file has JSON binding but no json:"-" tags to exclude fields
	if !reGoJSONBind.MatchString(ctx.Content) {
		return nil
	}
	if reGoJSONDash.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		if loc := reGoJSONBind.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Go struct binding from JSON without field exclusion tags",
				Description:   "JSON is decoded directly into a Go struct without using json:\"-\" tags to exclude sensitive fields. All exported struct fields will be bindable from user input, potentially including fields like IsAdmin, Role, or Password.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Use separate input DTOs with only the fields you want to accept. Or add json:\"-\" tags to sensitive fields: IsAdmin bool `json:\"-\"`. Consider using a binding struct distinct from your domain model.",
				CWEID:         "CWE-915",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"mass-assignment", "go", "json-binding", "cwe-915"},
			})
			return findings
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-MASS-010: PHP Eloquent $guarded Empty Array
// ---------------------------------------------------------------------------

type PHPEloquentGuardedEmpty struct{}

func (r *PHPEloquentGuardedEmpty) ID() string                     { return "GTSS-MASS-010" }
func (r *PHPEloquentGuardedEmpty) Name() string                   { return "PHPEloquentGuardedEmpty" }
func (r *PHPEloquentGuardedEmpty) DefaultSeverity() rules.Severity { return rules.High }
func (r *PHPEloquentGuardedEmpty) Languages() []rules.Language {
	return []rules.Language{rules.LangPHP}
}
func (r *PHPEloquentGuardedEmpty) Description() string {
	return "Detects Laravel Eloquent models with $guarded = [], which disables mass assignment protection and allows all attributes to be set."
}

func (r *PHPEloquentGuardedEmpty) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		if loc := rePHPGuardedEmpty.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Laravel Eloquent $guarded = [] disables mass assignment protection",
				Description:   "Setting $guarded to an empty array disables all mass assignment protection. Any attribute can be set through user input, including sensitive fields like is_admin, role, password, and foreign keys.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Use $fillable to explicitly list fields that can be mass-assigned: protected $fillable = ['name', 'email']. Or use $guarded to list sensitive fields: protected $guarded = ['id', 'is_admin', 'role'].",
				CWEID:         "CWE-915",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"mass-assignment", "laravel", "eloquent", "cwe-915"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&DjangoModelFormNoFields{})
	rules.Register(&SpringModelAttrNoInitBinder{})
	rules.Register(&ExpressBodyToDB{})
	rules.Register(&AspNetModelBindingNoBind{})
	rules.Register(&GoStructBindNoTags{})
	rules.Register(&PHPEloquentGuardedEmpty{})
}
