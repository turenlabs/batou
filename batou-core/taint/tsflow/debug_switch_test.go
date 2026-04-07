package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

func TestDebugSwitchAST(t *testing.T) {
	code := `
public class Test {
    public void doPost(javax.servlet.http.HttpServletRequest request) {
        String param = request.getHeader("Test");
        String bar;
        String guess = "ABC";
        char switchTarget = guess.charAt(1);
        switch (switchTarget) {
            case 'A':
                bar = param;
                break;
            case 'B':
                bar = "bob";
                break;
            default:
                bar = "safe";
                break;
        }
        System.out.println(bar);
    }
}
`
	tree := ast.Parse([]byte(code), rules.LangJava)
	if tree == nil {
		t.Fatal("parse failed")
	}
	root := tree.Root()
	
	// Find switch_expression or switch_statement
	var findNode func(n *ast.Node, depth int)
	findNode = func(n *ast.Node, depth int) {
		nodeType := n.Type()
		if nodeType == "switch_expression" || nodeType == "switch_statement" ||
			nodeType == "switch_block" || nodeType == "switch_block_statement_group" ||
			nodeType == "switch_label" || nodeType == "local_variable_declaration" {
			indent := ""
			for i := 0; i < depth; i++ {
				indent += "  "
			}
			text := n.Text()
			if len(text) > 80 {
				text = text[:80] + "..."
			}
			t.Logf("%s%s: %q", indent, nodeType, text)
			// Print children
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				ci := ""
				for j := 0; j < depth+1; j++ {
					ci += "  "
				}
				ctext := c.Text()
				if len(ctext) > 60 {
					ctext = ctext[:60] + "..."
				}
				t.Logf("%schild[%d] type=%s named=%v text=%q", ci, i, c.Type(), c.IsNamed(), ctext)
			}
		}
		for i := 0; i < n.ChildCount(); i++ {
			findNode(n.Child(i), depth+1)
		}
	}
	findNode(root, 0)
}
