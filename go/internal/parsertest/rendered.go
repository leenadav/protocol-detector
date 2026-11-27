package parsertest

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Rendered is a test's text of a value for leak checks: like fmt's %+v, but pointers and interfaces are followed
// to the values they hold. %+v prints a pointer field as its heap address, which hides the value behind it from
// the check and can itself contain a searched string ("135" in 0xc000135cf0), so a leak check on it is both blind
// and address-dependent.
func Rendered(v interface{}) string {
	var b strings.Builder
	renderValue(&b, reflect.ValueOf(v), 0)
	return b.String()
}

func renderValue(b *strings.Builder, v reflect.Value, depth int) {
	if depth > 32 {
		b.WriteString("…")
		return
	}
	switch v.Kind() {
	case reflect.Invalid:
		b.WriteString("<nil>")
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			b.WriteString("<nil>")
			return
		}
		renderValue(b, v.Elem(), depth+1)
	case reflect.Struct:
		b.WriteString("{")
		for i := 0; i < v.NumField(); i++ {
			if i > 0 {
				b.WriteString(" ")
			}
			b.WriteString(v.Type().Field(i).Name + ":")
			renderValue(b, v.Field(i), depth+1)
		}
		b.WriteString("}")
	case reflect.Slice, reflect.Array:
		b.WriteString("[")
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				b.WriteString(" ")
			}
			renderValue(b, v.Index(i), depth+1)
		}
		b.WriteString("]")
	case reflect.Map:
		keys := make([]string, 0, v.Len())
		values := map[string]reflect.Value{}
		for _, k := range v.MapKeys() {
			var kb strings.Builder
			renderValue(&kb, k, depth+1)
			keys = append(keys, kb.String())
			values[kb.String()] = v.MapIndex(k)
		}
		sort.Strings(keys)
		b.WriteString("map[")
		for i, k := range keys {
			if i > 0 {
				b.WriteString(" ")
			}
			b.WriteString(k + ":")
			renderValue(b, values[k], depth+1)
		}
		b.WriteString("]")
	case reflect.String:
		b.WriteString(v.String())
	case reflect.Bool:
		fmt.Fprint(b, v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		fmt.Fprint(b, v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		fmt.Fprint(b, v.Uint())
	case reflect.Float32, reflect.Float64:
		fmt.Fprint(b, v.Float())
	default: // funcs, channels: their identity is not content
		b.WriteString("<" + v.Kind().String() + ">")
	}
}
