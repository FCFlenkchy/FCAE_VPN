// Package expvar isolates Mihomo's Tailscale metrics from sing-box's fork.
package expvar

import (
	standard "expvar"
	"net/http"
	"strings"
)

type Var = standard.Var
type Int = standard.Int
type Float = standard.Float
type String = standard.String
type Map = standard.Map
type Func = standard.Func
type KeyValue = standard.KeyValue

const prefix = "fcae_mihomo_"

func Publish(name string, value Var) { standard.Publish(prefix+name, value) }
func Get(name string) Var            { return standard.Get(prefix + name) }
func NewInt(name string) *Int        { return standard.NewInt(prefix + name) }
func NewFloat(name string) *Float    { return standard.NewFloat(prefix + name) }
func NewString(name string) *String  { return standard.NewString(prefix + name) }
func NewMap(name string) *Map        { return standard.NewMap(prefix + name) }
func Handler() http.Handler          { return standard.Handler() }
func Do(f func(KeyValue)) {
	standard.Do(func(kv KeyValue) {
		if name, ok := strings.CutPrefix(kv.Key, prefix); ok {
			kv.Key = name
			f(kv)
		}
	})
}
