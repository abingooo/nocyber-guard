package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const sampleSeparator = "\n\n[... content sampled ...]\n\n"

// ParseResponses implements the deliberately narrow v0.1 contract. It first
// selects a valid top-level instructions string. Only when that is unavailable
// does it use input[1].content, and that content must contain only input_text
// blocks. All JSON object keys, including keys in skipped values, are checked
// for duplicates.
func ParseResponses(ctx context.Context, body []byte, maxDepth int) (Parsed, error) {
	parsed := Parsed{
		Instructions: Field{Name: "instructions", State: FieldMissing},
		Input1:       Field{Name: "input1", State: FieldMissing},
	}
	if len(body) == 0 || !utf8.Valid(body) {
		return parsed, ErrInvalidJSON
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if maxDepth <= 0 {
		maxDepth = DefaultJSONDepth
	}
	cursor := jsonCursor{ctx: ctx, decoder: json.NewDecoder(bytes.NewReader(body)), maxDepth: maxDepth}
	cursor.decoder.UseNumber()

	start, err := cursor.token()
	if err != nil || start != json.Delim('{') {
		return parsed, wrapJSONError(err)
	}
	seen := make(map[string]struct{})
	for cursor.decoder.More() {
		key, err := cursor.objectKey(seen)
		if err != nil {
			return parsed, wrapJSONError(err)
		}
		switch key {
		case "instructions":
			parsed.Instructions, err = parseInstructions(&cursor)
		case "input":
			parsed.Input1, err = parseInput(&cursor)
		case "model":
			var valid bool
			parsed.Model, valid, err = cursor.stringValue(1)
			if !valid || len(parsed.Model) > 256 || !validMetadataText(parsed.Model) {
				parsed.Model = ""
			}
		default:
			err = cursor.skipValue(1)
		}
		if err != nil {
			return parsed, wrapJSONError(err)
		}
	}
	end, err := cursor.token()
	if err != nil || end != json.Delim('}') {
		return parsed, wrapJSONError(err)
	}
	if err := ensureJSONEOF(cursor.decoder); err != nil {
		return parsed, wrapJSONError(err)
	}

	parsed.SelectedName, parsed.Selected = SelectField(parsed)
	return parsed, nil
}

func SelectField(parsed Parsed) (string, Field) {
	if parsed.Instructions.IsValid() {
		return parsed.Instructions.Name, parsed.Instructions
	}
	if parsed.Input1.IsValid() {
		return parsed.Input1.Name, parsed.Input1
	}
	return "", Field{State: FieldEmpty}
}

// PrepareAISample returns the original field plus a rune-safe AI sample. The
// stored hash always represents the complete exact text, not the sample.
func PrepareAISample(field Field, maxRunes int) Field {
	if !field.IsValid() {
		return field
	}
	if maxRunes <= 0 {
		maxRunes = DefaultMaxPromptRunes
	}
	if field.Runes <= maxRunes {
		field.AISample = field.Text
		field.AISampled = false
		return field
	}
	first := maxRunes * 2 / 3
	last := maxRunes - first
	firstEnd := byteOffsetAtRune(field.Text, first)
	lastStart := byteOffsetAtRune(field.Text, field.Runes-last)
	field.AISample = field.Text[:firstEnd] + sampleSeparator + field.Text[lastStart:]
	field.AISampled = true
	return field
}

func byteOffsetAtRune(value string, runeOffset int) int {
	if runeOffset <= 0 {
		return 0
	}
	count := 0
	for offset := range value {
		if count == runeOffset {
			return offset
		}
		count++
	}
	return len(value)
}

func validMetadataText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func parseInstructions(cursor *jsonCursor) (Field, error) {
	field := Field{Name: "instructions", State: FieldInvalid}
	token, err := cursor.token()
	if err != nil {
		return field, err
	}
	if value, ok := token.(string); ok {
		return newTextField("instructions", value), nil
	}
	if delimiter, ok := token.(json.Delim); ok {
		if err := cursor.skipDelimited(delimiter, 1); err != nil {
			return field, err
		}
	}
	return field, nil
}

func parseInput(cursor *jsonCursor) (Field, error) {
	result := Field{Name: "input1", State: FieldMissing}
	token, err := cursor.token()
	if err != nil {
		return result, err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '[' {
		if ok {
			if err := cursor.skipDelimited(delimiter, 1); err != nil {
				return result, err
			}
		}
		result.State = FieldInvalid
		return result, nil
	}

	index := 0
	for cursor.decoder.More() {
		if index == 1 {
			result, err = parseInputItem(cursor)
		} else {
			err = cursor.skipValue(2)
		}
		if err != nil {
			return Field{Name: "input1", State: FieldInvalid}, err
		}
		index++
	}
	end, err := cursor.token()
	if err != nil || end != json.Delim(']') {
		return Field{Name: "input1", State: FieldInvalid}, wrapJSONError(err)
	}
	return result, nil
}

func parseInputItem(cursor *jsonCursor) (Field, error) {
	result := Field{Name: "input1", State: FieldInvalid}
	token, err := cursor.token()
	if err != nil {
		return result, err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		if ok {
			if err := cursor.skipDelimited(delimiter, 2); err != nil {
				return result, err
			}
		}
		return result, nil
	}

	contentSeen := false
	seen := make(map[string]struct{})
	for cursor.decoder.More() {
		key, err := cursor.objectKey(seen)
		if err != nil {
			return result, err
		}
		if key == "content" {
			contentSeen = true
			result, err = parseContent(cursor)
		} else {
			err = cursor.skipValue(3)
		}
		if err != nil {
			return result, err
		}
	}
	end, err := cursor.token()
	if err != nil || end != json.Delim('}') {
		return result, wrapJSONError(err)
	}
	if !contentSeen {
		result.State = FieldInvalid
	}
	return result, nil
}

func parseContent(cursor *jsonCursor) (Field, error) {
	result := Field{Name: "input1", State: FieldInvalid}
	token, err := cursor.token()
	if err != nil {
		return result, err
	}
	if value, ok := token.(string); ok {
		return newTextField("input1", value), nil
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '[' {
		if ok {
			if err := cursor.skipDelimited(delimiter, 3); err != nil {
				return result, err
			}
		}
		return result, nil
	}

	var content bytes.Buffer
	invalid := false
	for cursor.decoder.More() {
		text, recognized, valid, err := parseContentBlock(cursor)
		if err != nil {
			return result, err
		}
		if !recognized || !valid {
			invalid = true
			continue
		}
		content.WriteString(text)
	}
	end, err := cursor.token()
	if err != nil || end != json.Delim(']') {
		return result, wrapJSONError(err)
	}
	if invalid {
		return result, nil
	}
	return newTextField("input1", content.String()), nil
}

func parseContentBlock(cursor *jsonCursor) (text string, recognized, valid bool, err error) {
	token, err := cursor.token()
	if err != nil {
		return "", false, false, err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		if ok {
			if err := cursor.skipDelimited(delimiter, 4); err != nil {
				return "", false, false, err
			}
		}
		return "", false, false, nil
	}

	var blockType, textValue string
	var typeSeen, typeValid, textSeen, textValid bool
	seen := make(map[string]struct{})
	for cursor.decoder.More() {
		key, err := cursor.objectKey(seen)
		if err != nil {
			return "", false, false, err
		}
		switch key {
		case "type":
			typeSeen = true
			blockType, typeValid, err = cursor.stringValue(5)
		case "text":
			textSeen = true
			textValue, textValid, err = cursor.stringValue(5)
		default:
			err = cursor.skipValue(5)
		}
		if err != nil {
			return "", false, false, err
		}
	}
	end, err := cursor.token()
	if err != nil || end != json.Delim('}') {
		return "", false, false, wrapJSONError(err)
	}
	if !typeSeen || !typeValid || blockType != "input_text" {
		return "", false, false, nil
	}
	return textValue, true, textSeen && textValid, nil
}

func newTextField(name, text string) Field {
	if text == "" {
		return Field{Name: name, State: FieldEmpty}
	}
	digest := sha256.Sum256([]byte(text))
	return Field{
		Name: name, State: FieldValid, Text: text,
		SHA256: hex.EncodeToString(digest[:]), Bytes: len([]byte(text)), Runes: utf8.RuneCountInString(text),
	}
}

type jsonCursor struct {
	ctx      context.Context
	decoder  *json.Decoder
	maxDepth int
	tokens   uint64
}

func (cursor *jsonCursor) token() (json.Token, error) {
	if cursor == nil || cursor.decoder == nil {
		return nil, ErrInvalidJSON
	}
	cursor.tokens++
	select {
	case <-cursor.ctx.Done():
		return nil, cursor.ctx.Err()
	default:
	}
	return cursor.decoder.Token()
}

func (cursor *jsonCursor) objectKey(seen map[string]struct{}) (string, error) {
	token, err := cursor.token()
	if err != nil {
		return "", err
	}
	key, ok := token.(string)
	if !ok {
		return "", ErrInvalidJSON
	}
	if _, duplicate := seen[key]; duplicate {
		return "", fmt.Errorf("%w: %s", ErrDuplicateKey, key)
	}
	seen[key] = struct{}{}
	return key, nil
}

func (cursor *jsonCursor) stringValue(depth int) (string, bool, error) {
	token, err := cursor.token()
	if err != nil {
		return "", false, err
	}
	if value, ok := token.(string); ok {
		return value, true, nil
	}
	if delimiter, ok := token.(json.Delim); ok {
		if err := cursor.skipDelimited(delimiter, depth); err != nil {
			return "", false, err
		}
	}
	return "", false, nil
}

func (cursor *jsonCursor) skipValue(depth int) error {
	if depth > cursor.maxDepth {
		return ErrJSONDepth
	}
	token, err := cursor.token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); ok {
		return cursor.skipDelimited(delimiter, depth)
	}
	return nil
}

func (cursor *jsonCursor) skipDelimited(delimiter json.Delim, depth int) error {
	if depth > cursor.maxDepth {
		return ErrJSONDepth
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for cursor.decoder.More() {
			if _, err := cursor.objectKey(seen); err != nil {
				return err
			}
			if err := cursor.skipValue(depth + 1); err != nil {
				return err
			}
		}
		end, err := cursor.token()
		if err != nil || end != json.Delim('}') {
			return wrapJSONError(err)
		}
	case '[':
		for cursor.decoder.More() {
			if err := cursor.skipValue(depth + 1); err != nil {
				return err
			}
		}
		end, err := cursor.token()
		if err != nil || end != json.Delim(']') {
			return wrapJSONError(err)
		}
	default:
		return ErrInvalidJSON
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("unexpected trailing JSON value")
	}
	return err
}

func wrapJSONError(err error) error {
	if err == nil {
		return ErrInvalidJSON
	}
	if errors.Is(err, ErrInvalidJSON) || errors.Is(err, ErrJSONDepth) || errors.Is(err, ErrDuplicateKey) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrInvalidJSON, err)
}
