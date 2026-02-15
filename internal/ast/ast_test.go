package ast

import (
	"testing"

	"github.com/turenio/gtss/internal/rules"
)

func TestParse_Go(t *testing.T) {
	src := []byte(`package main

import "fmt"

func main() {
	fmt.Println("hello")
}
`)
	tree := Parse(src, rules.LangGo)
	if tree == nil {
		t.Fatal("expected non-nil tree for Go")
	}
	root := tree.Root()
	if root == nil {
		t.Fatal("expected non-nil root node")
	}
	if root.Type() != "source_file" {
		t.Errorf("root type = %q, want source_file", root.Type())
	}
	if root.ChildCount() == 0 {
		t.Error("expected children on root node")
	}
	if tree.Language() != "go" {
		t.Errorf("tree.Language() = %q, want go", tree.Language())
	}
}

func TestParse_Python(t *testing.T) {
	src := []byte(`
def hello():
    print("hello world")

# a comment
x = 42
`)
	tree := Parse(src, rules.LangPython)
	if tree == nil {
		t.Fatal("expected non-nil tree for Python")
	}
	root := tree.Root()
	if root.Type() != "module" {
		t.Errorf("root type = %q, want module", root.Type())
	}
}

func TestParse_JavaScript(t *testing.T) {
	src := []byte(`
function greet(name) {
  // say hi
  console.log("Hello " + name);
}
`)
	tree := Parse(src, rules.LangJavaScript)
	if tree == nil {
		t.Fatal("expected non-nil tree for JavaScript")
	}
	root := tree.Root()
	if root.Type() != "program" {
		t.Errorf("root type = %q, want program", root.Type())
	}
}

func TestParse_TypeScript(t *testing.T) {
	src := []byte(`
interface User {
  name: string;
  age: number;
}

function greet(user: User): string {
  return "Hello " + user.name;
}
`)
	tree := Parse(src, rules.LangTypeScript)
	if tree == nil {
		t.Fatal("expected non-nil tree for TypeScript")
	}
}

func TestParse_Java(t *testing.T) {
	src := []byte(`
public class Hello {
    public static void main(String[] args) {
        System.out.println("Hello");
    }
}
`)
	tree := Parse(src, rules.LangJava)
	if tree == nil {
		t.Fatal("expected non-nil tree for Java")
	}
}

func TestParse_PHP(t *testing.T) {
	src := []byte(`<?php
function greet($name) {
    echo "Hello " . $name;
}
?>`)
	tree := Parse(src, rules.LangPHP)
	if tree == nil {
		t.Fatal("expected non-nil tree for PHP")
	}
}

func TestParse_Ruby(t *testing.T) {
	src := []byte(`
def hello(name)
  puts "Hello #{name}"
end
`)
	tree := Parse(src, rules.LangRuby)
	if tree == nil {
		t.Fatal("expected non-nil tree for Ruby")
	}
}

func TestParse_C(t *testing.T) {
	src := []byte(`
#include <stdio.h>
int main() {
    printf("hello\n");
    return 0;
}
`)
	tree := Parse(src, rules.LangC)
	if tree == nil {
		t.Fatal("expected non-nil tree for C")
	}
}

func TestParse_CPP(t *testing.T) {
	src := []byte(`
#include <iostream>
int main() {
    std::cout << "hello" << std::endl;
    return 0;
}
`)
	tree := Parse(src, rules.LangCPP)
	if tree == nil {
		t.Fatal("expected non-nil tree for C++")
	}
}

func TestParse_CSharp(t *testing.T) {
	src := []byte(`
using System;
class Hello {
    static void Main() {
        Console.WriteLine("Hello");
    }
}
`)
	tree := Parse(src, rules.LangCSharp)
	if tree == nil {
		t.Fatal("expected non-nil tree for C#")
	}
}

func TestParse_Kotlin(t *testing.T) {
	src := []byte(`
fun main() {
    println("Hello")
}
`)
	tree := Parse(src, rules.LangKotlin)
	if tree == nil {
		t.Fatal("expected non-nil tree for Kotlin")
	}
}

func TestParse_Swift(t *testing.T) {
	src := []byte(`
import Foundation
func greet(_ name: String) -> String {
    return "Hello \(name)"
}
`)
	tree := Parse(src, rules.LangSwift)
	if tree == nil {
		t.Fatal("expected non-nil tree for Swift")
	}
}

func TestParse_Rust(t *testing.T) {
	src := []byte(`
fn main() {
    println!("Hello");
}
`)
	tree := Parse(src, rules.LangRust)
	if tree == nil {
		t.Fatal("expected non-nil tree for Rust")
	}
}

func TestParse_Lua(t *testing.T) {
	src := []byte(`
function greet(name)
    print("Hello " .. name)
end
`)
	tree := Parse(src, rules.LangLua)
	if tree == nil {
		t.Fatal("expected non-nil tree for Lua")
	}
}

func TestParse_Groovy(t *testing.T) {
	src := []byte(`
def greet(name) {
    println "Hello $name"
}
`)
	tree := Parse(src, rules.LangGroovy)
	if tree == nil {
		t.Fatal("expected non-nil tree for Groovy")
	}
}

func TestParse_UnsupportedLanguage(t *testing.T) {
	src := []byte(`some content`)
	tree := Parse(src, rules.LangDocker)
	if tree != nil {
		t.Error("expected nil tree for unsupported language (Docker)")
	}
}

func TestParse_EmptyContent(t *testing.T) {
	tree := Parse([]byte{}, rules.LangGo)
	// Empty content may or may not parse depending on grammar.
	// Just verify no panic.
	_ = tree
}

func TestNodeWalk(t *testing.T) {
	src := []byte(`package main

func hello() {
	x := 1
}
`)
	tree := Parse(src, rules.LangGo)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}

	var count int
	tree.Root().Walk(func(n *Node) bool {
		count++
		return true
	})
	if count == 0 {
		t.Error("walk visited no nodes")
	}
}

func TestNodeText(t *testing.T) {
	src := []byte(`package main`)
	tree := Parse(src, rules.LangGo)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}
	root := tree.Root()
	text := root.Text()
	if text != "package main" {
		t.Errorf("root text = %q, want %q", text, "package main")
	}
}

func TestNodeAncestors(t *testing.T) {
	src := []byte(`package main

func foo() {
	x := 1
}
`)
	tree := Parse(src, rules.LangGo)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}

	// Find a deep node and check its ancestors.
	var deepest *Node
	tree.Root().Walk(func(n *Node) bool {
		deepest = n
		return true
	})
	if deepest == nil {
		t.Fatal("no nodes found")
	}
	ancestors := deepest.Ancestors()
	if len(ancestors) == 0 {
		t.Error("expected non-empty ancestors for a deep node")
	}
	// The last ancestor should be the root.
	last := ancestors[len(ancestors)-1]
	if last.Type() != "source_file" {
		t.Errorf("topmost ancestor type = %q, want source_file", last.Type())
	}
}

func TestFindByType(t *testing.T) {
	src := []byte(`
// a comment
package main

// another comment
func foo() {}
`)
	tree := Parse(src, rules.LangGo)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}
	comments := FindByType(tree.Root(), "comment")
	if len(comments) < 2 {
		t.Errorf("expected at least 2 comments, got %d", len(comments))
	}
}

func TestNodeAtOffset(t *testing.T) {
	src := []byte(`package main`)
	tree := Parse(src, rules.LangGo)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}
	node := NodeAtOffset(tree.Root(), 0)
	if node == nil {
		t.Fatal("expected non-nil node at offset 0")
	}
}

func TestSupportsLanguage(t *testing.T) {
	if !SupportsLanguage(rules.LangGo) {
		t.Error("expected Go to be supported")
	}
	if !SupportsLanguage(rules.LangPython) {
		t.Error("expected Python to be supported")
	}
	if !SupportsLanguage(rules.LangPerl) {
		t.Error("expected Perl to be supported")
	}
	if SupportsLanguage(rules.LangDocker) {
		t.Error("expected Docker to NOT be supported")
	}
}

func TestNilTreeMethods(t *testing.T) {
	var tree *Tree
	if tree.Root() != nil {
		t.Error("nil tree Root() should return nil")
	}
	if tree.Content() != nil {
		t.Error("nil tree Content() should return nil")
	}
	if tree.Language() != "" {
		t.Error("nil tree Language() should return empty string")
	}
}

func TestNilNodeMethods(t *testing.T) {
	var n *Node
	if n.Type() != "" {
		t.Error("nil node Type() should return empty string")
	}
	if n.Text() != "" {
		t.Error("nil node Text() should return empty string")
	}
	if n.ChildCount() != 0 {
		t.Error("nil node ChildCount() should return 0")
	}
	if n.Child(0) != nil {
		t.Error("nil node Child() should return nil")
	}
	if n.Parent() != nil {
		t.Error("nil node Parent() should return nil")
	}
	if n.IsNamed() {
		t.Error("nil node IsNamed() should return false")
	}
	n.Walk(func(*Node) bool { return true }) // should not panic
}
