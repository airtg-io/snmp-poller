package config

import (
	"errors"
	"math/big"
	"testing"
)

func TestFormula(t *testing.T) {
	env := map[string]*big.Rat{
		"units": big.NewRat(4096, 1),
		"size":  big.NewRat(2147483647, 1), // Integer32 max
		"used":  big.NewRat(1000, 1),
		"zero":  new(big.Rat),
		"half":  big.NewRat(1, 2),
	}
	lookup := func(n string) (*big.Rat, bool) { v, ok := env[n]; return v, ok }
	for _, tc := range []struct {
		src  string
		want any
		refs int
	}{
		{"size * units", int64(8796093018112), 2}, // exact: 2^31-1 times 4096
		{"(size - used) * units", int64(8796088922112), 3},
		{"1 + 2 * 3", int64(7), 0},
		{"(1 + 2) * 3", int64(9), 0},
		{"10 - 4 - 3", int64(3), 0}, // left associative
		{"-used + -(-2)", int64(-998), 1},
		{"used * 100 / 4000", 25.0, 1}, // a division: always a float, even when integral
		{"used / 3", 1000.0 / 3, 1},
		{"used * 1.5", 1500.0, 1},                                                   // a decimal number: a float
		{"used * half + half", 500.5, 2},                                            // a float input, a result that is not an integer
		{"units * units * units * units * units * units", float64(1<<62) * 1024, 1}, // 2^72 overflows int64
		{"  used  ", int64(1000), 1},
	} {
		f, err := ParseFormula(tc.src)
		if err != nil {
			t.Fatalf("%q: %v", tc.src, err)
		}
		r, err := f.Eval(lookup)
		if err != nil {
			t.Fatalf("%q: %v", tc.src, err)
		}
		if got := f.Value(r); got != tc.want {
			t.Errorf("%q = %v (%T), want %v (%T)", tc.src, got, got, tc.want, tc.want)
		}
		if len(f.Refs()) != tc.refs {
			t.Errorf("%q refs = %v, want %d", tc.src, f.Refs(), tc.refs)
		}
	}
	for src, want := range map[string]error{
		"used / zero":          ErrDivisionByZero,
		"used / (size - size)": ErrDivisionByZero,
		"used + missing":       ErrMissingValue,
	} {
		f, err := ParseFormula(src)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Eval(lookup); !errors.Is(err, want) {
			t.Errorf("%q: err = %v, want %v", src, err, want)
		}
	}
	for _, src := range []string{"", "1 +", "* 2", "(1", "1)", "a b", "1..2", "2.", "a % b", "$x"} {
		if _, err := ParseFormula(src); err == nil {
			t.Errorf("%q: parsed, want an error", src)
		}
	}
}
