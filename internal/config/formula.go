package config

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Formula is a compiled arithmetic expression over other values of the same
// row (table columns) or of the same capability (scalars), e.g.
// "hrStorageSize * hrStorageAllocationUnits".
//
// Syntax: decimal numbers (1024, 0.5), names, + - * /, unary minus and
// parentheses, with the usual precedence. Arithmetic is exact (rational
// numbers): products of large counters lose no precision, and only the
// final result is rounded when it is not an integer.
//
// The result type depends on the formula only, so a metric never changes
// type between polls: a formula with a division or a decimal number gives
// a float64, any other an int64 (a float64 if the value does not fit, or
// is not an integer because an input is a float).
type Formula struct {
	src   string
	root  node
	refs  []string
	float bool
}

// Errors returned by Formula.Eval. Neither is a configuration error: the
// value is just not computable on this poll.
var (
	// ErrMissingValue: a referenced value was not returned by the agent,
	// or is not a number.
	ErrMissingValue = errors.New("missing value")
	// ErrDivisionByZero: a divisor is zero (e.g. a storage of size 0).
	ErrDivisionByZero = errors.New("division by zero")
)

// String returns the formula as written.
func (f *Formula) String() string { return f.src }

// Refs returns the names the formula reads, in order of first use.
func (f *Formula) Refs() []string { return f.refs }

// Value converts a result to the formula's Go type: int64 or float64.
func (f *Formula) Value(r *big.Rat) any {
	if !f.float && r.IsInt() && r.Num().IsInt64() {
		return r.Num().Int64()
	}
	v, _ := r.Float64()
	return v
}

// Eval computes the formula. lookup returns the value of a name, or false
// when it is missing.
func (f *Formula) Eval(lookup func(name string) (*big.Rat, bool)) (*big.Rat, error) {
	return f.root.eval(lookup)
}

type node interface {
	eval(lookup func(string) (*big.Rat, bool)) (*big.Rat, error)
}

type numNode struct{ v *big.Rat }

func (n numNode) eval(func(string) (*big.Rat, bool)) (*big.Rat, error) { return n.v, nil }

type refNode struct{ name string }

func (n refNode) eval(lookup func(string) (*big.Rat, bool)) (*big.Rat, error) {
	v, ok := lookup(n.name)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrMissingValue, n.name)
	}
	return v, nil
}

type negNode struct{ x node }

func (n negNode) eval(lookup func(string) (*big.Rat, bool)) (*big.Rat, error) {
	v, err := n.x.eval(lookup)
	if err != nil {
		return nil, err
	}
	return new(big.Rat).Neg(v), nil
}

type binNode struct {
	op   byte
	l, r node
}

func (n binNode) eval(lookup func(string) (*big.Rat, bool)) (*big.Rat, error) {
	l, err := n.l.eval(lookup)
	if err != nil {
		return nil, err
	}
	r, err := n.r.eval(lookup)
	if err != nil {
		return nil, err
	}
	z := new(big.Rat)
	switch n.op {
	case '+':
		return z.Add(l, r), nil
	case '-':
		return z.Sub(l, r), nil
	case '*':
		return z.Mul(l, r), nil
	}
	if r.Sign() == 0 {
		return nil, ErrDivisionByZero
	}
	return z.Quo(l, r), nil
}

// ParseFormula compiles src.
func ParseFormula(src string) (*Formula, error) {
	p := &formulaParser{src: src}
	p.next()
	root, err := p.expr()
	if err == nil && p.tok.kind != tokEnd {
		err = p.errorf("unexpected %s", p.tok)
	}
	if err != nil {
		return nil, err
	}
	return &Formula{src: strings.TrimSpace(src), root: root, refs: p.refs, float: p.float}, nil
}

type tokKind int

const (
	tokEnd tokKind = iota
	tokNum
	tokName
	tokOp
	tokBad
)

type token struct {
	kind tokKind
	text string
	pos  int
}

func (t token) String() string {
	if t.kind == tokEnd {
		return "end of formula"
	}
	return fmt.Sprintf("%q", t.text)
}

type formulaParser struct {
	src   string
	pos   int
	tok   token
	refs  []string
	float bool // a division or a decimal number
}

func (p *formulaParser) errorf(format string, a ...any) error {
	return fmt.Errorf("formula %q: at column %d: %s", p.src, p.tok.pos+1, fmt.Sprintf(format, a...))
}

func isNameStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func (p *formulaParser) next() {
	for p.pos < len(p.src) && strings.IndexByte(" \t\r\n", p.src[p.pos]) >= 0 {
		p.pos++
	}
	start := p.pos
	if p.pos >= len(p.src) {
		p.tok = token{kind: tokEnd, pos: start}
		return
	}
	c := p.src[p.pos]
	switch {
	case isNameStart(c):
		for p.pos < len(p.src) && (isNameStart(p.src[p.pos]) || isDigit(p.src[p.pos])) {
			p.pos++
		}
		p.tok = token{kind: tokName, text: p.src[start:p.pos], pos: start}
	case isDigit(c):
		for p.pos < len(p.src) && (isDigit(p.src[p.pos]) || p.src[p.pos] == '.') {
			p.pos++
		}
		p.tok = token{kind: tokNum, text: p.src[start:p.pos], pos: start}
	case strings.IndexByte("+-*/()", c) >= 0:
		p.pos++
		p.tok = token{kind: tokOp, text: string(c), pos: start}
	default:
		p.pos++
		p.tok = token{kind: tokBad, text: string(c), pos: start}
	}
}

func (p *formulaParser) isOp(ops string) bool {
	return p.tok.kind == tokOp && strings.Contains(ops, p.tok.text)
}

// expr := term (("+" | "-") term)*
func (p *formulaParser) expr() (node, error) {
	l, err := p.term()
	for err == nil && p.isOp("+-") {
		op := p.tok.text[0]
		p.next()
		var r node
		if r, err = p.term(); err == nil {
			l = binNode{op: op, l: l, r: r}
		}
	}
	return l, err
}

// term := unary (("*" | "/") unary)*
func (p *formulaParser) term() (node, error) {
	l, err := p.unary()
	for err == nil && p.isOp("*/") {
		op := p.tok.text[0]
		p.float = p.float || op == '/'
		p.next()
		var r node
		if r, err = p.unary(); err == nil {
			l = binNode{op: op, l: l, r: r}
		}
	}
	return l, err
}

// unary := "-" unary | primary
func (p *formulaParser) unary() (node, error) {
	if p.isOp("-") {
		p.next()
		x, err := p.unary()
		return negNode{x: x}, err
	}
	return p.primary()
}

// primary := number | name | "(" expr ")"
func (p *formulaParser) primary() (node, error) {
	t := p.tok
	switch {
	case t.kind == tokNum:
		v, ok := new(big.Rat).SetString(t.text)
		if !ok || strings.Count(t.text, ".") > 1 || strings.HasSuffix(t.text, ".") {
			return nil, p.errorf("invalid number %q", t.text)
		}
		p.float = p.float || strings.Contains(t.text, ".")
		p.next()
		return numNode{v: v}, nil
	case t.kind == tokName:
		p.next()
		found := false
		for _, r := range p.refs {
			found = found || r == t.text
		}
		if !found {
			p.refs = append(p.refs, t.text)
		}
		return refNode{name: t.text}, nil
	case p.isOp("("):
		p.next()
		x, err := p.expr()
		if err != nil {
			return nil, err
		}
		if !p.isOp(")") {
			return nil, p.errorf("expected \")\", got %s", p.tok)
		}
		p.next()
		return x, nil
	}
	return nil, p.errorf("expected a number, a name or \"(\", got %s", t)
}
