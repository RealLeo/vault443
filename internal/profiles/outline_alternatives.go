package profiles

import (
	"errors"
	"sort"

	"vault443/internal/model"
)

var errOutlineSearchLimit = errors.New("Outline alternatives exceed the bounded search limit (256 configurations)")

// Resolve complete graphs before choosing Xray versus the SDK. In particular,
// an ordinary SS2022 transport is supported even when wrapped in alternatives.
// Lexicographic object keys put TCP before UDP; alternatives retain input order.
func selectOutline(value any, sourceURL, name string) (model.Profile, error) {
	var selected model.Profile
	last := errors.New("no supported Outline alternative")
	remaining, configurations := 65536, 0
	found, err := expandOutline(value, &remaining, func(candidate any) (bool, error) {
		configurations++
		if configurations > 256 {
			return false, errOutlineSearchLimit
		}
		p, e := parseResolvedOutline(candidate, sourceURL, name)
		if e != nil {
			last = e
			return false, nil
		}
		selected = p
		return true, nil
	})
	if err != nil {
		return model.Profile{}, err
	}
	if !found {
		return model.Profile{}, last
	}
	return selected, nil
}

func expandOutline(value any, remaining *int, visit func(any) (bool, error)) (bool, error) {
	*remaining--
	if *remaining < 0 {
		return false, errOutlineSearchLimit
	}
	m, ok := value.(map[string]any)
	if !ok {
		return visit(value)
	}
	if m["$type"] == "first-supported" {
		if onlyKeys(m, "$type", "options") != nil {
			return false, nil
		}
		options, ok := m["options"].([]any)
		if !ok || len(options) == 0 || len(options) > 8 {
			return false, nil
		}
		for _, option := range options {
			if done, err := expandOutline(option, remaining, visit); done || err != nil {
				return done, err
			}
		}
		return false, nil
	}
	keys := make([]string, 0, len(m))
	resolved := make(map[string]any, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var field func(int) (bool, error)
	field = func(i int) (bool, error) {
		if i == len(keys) {
			return visit(resolved)
		}
		key := keys[i]
		return expandOutline(m[key], remaining, func(v any) (bool, error) {
			resolved[key] = v
			return field(i + 1)
		})
	}
	return field(0)
}
