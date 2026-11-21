package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// decodeConfig fills dst, a pointer to the struct CreateConfig returned, from the middleware's
// `config` JSON. Keys match a field by its `mapstructure` or `json` tag name, or by its Go name,
// ignoring case, as Traefik's own decoder does. A key that matches no field is an error: a
// plugin whose option was misspelled must not run with the default.
//
// Structs inside structs are matched the same way. Values of slices and maps go through
// encoding/json with unknown fields refused (json tags only).
func decodeConfig(dst reflect.Value, raw []byte) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil
	}
	if dst.Kind() != reflect.Ptr || dst.IsNil() || dst.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("CreateConfig must return a pointer to a struct, not %s", dst.Type())
	}
	return decodeStruct(dst.Elem(), raw, "")
}

type configField struct {
	index int
	names []string
}

func configFields(t reflect.Type) []configField {
	var fields []configField
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		names := []string{}
		skip := false
		for _, key := range []string{"mapstructure", "json"} {
			tag, ok := f.Tag.Lookup(key)
			if !ok {
				continue
			}
			name, _, _ := strings.Cut(tag, ",")
			if name == "-" {
				skip = true
			} else if name != "" {
				names = append(names, name)
			}
		}
		if skip {
			continue
		}
		fields = append(fields, configField{index: i, names: append(names, f.Name)})
	}
	return fields
}

func decodeStruct(v reflect.Value, raw []byte, at string) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		if at == "" {
			return fmt.Errorf("the config is not a JSON object: %w", err)
		}
		return fmt.Errorf("%s is not a JSON object: %w", at, err)
	}
	fields := configFields(v.Type())
	for key, value := range object {
		field, ok := findField(fields, key)
		if !ok {
			return fmt.Errorf("unknown config field %q%s", key, inside(at))
		}
		if err := decodeValue(v.Field(field.index), value, join(at, key)); err != nil {
			return err
		}
	}
	return nil
}

func inside(at string) string {
	if at == "" {
		return ""
	}
	return " in " + at
}

func join(at, key string) string {
	if at == "" {
		return key
	}
	return at + "." + key
}

// findField prefers an exact name over a case-insensitive one.
func findField(fields []configField, key string) (configField, bool) {
	for _, f := range fields {
		if contains(f.names, key) {
			return f, true
		}
	}
	for _, f := range fields {
		for _, name := range f.names {
			if strings.EqualFold(name, key) {
				return f, true
			}
		}
	}
	return configField{}, false
}

func decodeValue(dst reflect.Value, raw []byte, at string) error {
	t := dst.Type()
	if t.Kind() == reflect.Ptr && t.Elem().Kind() == reflect.Struct {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			dst.Set(reflect.Zero(t))
			return nil
		}
		if dst.IsNil() {
			dst.Set(reflect.New(t.Elem()))
		}
		return decodeStruct(dst.Elem(), raw, at)
	}
	if t.Kind() == reflect.Struct {
		return decodeStruct(dst, raw, at)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst.Addr().Interface()); err != nil {
		return fmt.Errorf("config field %s: %w", at, err)
	}
	return nil
}
