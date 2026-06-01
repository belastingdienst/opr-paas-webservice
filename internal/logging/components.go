package logging

import "strings"

// Components is a map that holds components and their Debug state (false is InfoLevel, True is DebugLevel)
type Components map[Component]bool

// Component is a custom type, so that we can use it as an ENUM
type Component int

const (
	// RuntimeComponent represents a logging component for the runtime controller
	// (Note: As the runtime logger is only fetched once, changing debuglevel with PaasConfix has no effect.)
	RuntimeComponent Component = iota
	// RouterComponent represents a logging component for the runtime controller.
	// Note: As the runtime logger is only fetched once, changing debuglevel with PaasConfix has no effect.
	RouterComponent Component = iota

	// EncryptComponent is used for loggin regarding the Secret Encryption webcall.
	EncryptComponent Component = iota
	// CheckPaasComponent is used for loggin regarding the Paas check webcall.
	CheckPaasComponent Component = iota

	// UnknownComponent represents a logging component with unknown origin
	UnknownComponent Component = iota
	// TestComponent represents a logging component only used in unittests
	TestComponent Component = iota
)

var (
	componentConverter = map[string]Component{
		"runtime": RuntimeComponent,
		"router":  RouterComponent,

		"encrypt":    EncryptComponent,
		"check_paas": CheckPaasComponent,

		"undefined_component": UnknownComponent,
		"unittest_component":  TestComponent,
	}
	reverseComponentConverter map[Component]string
)

func componentToString(component Component) string {
	revConverter := map[Component]string{}
	if reverseComponentConverter == nil {
		for s, comp := range componentConverter {
			revConverter[comp] = s
		}
	}
	if s, exists := revConverter[component]; exists {
		return s
	}
	return "undefined_component"
}

// NewComponentsFromString takes a comma separated string (as used in command arguments) and converts it into a
// Components object
func NewComponentsFromString(commaSeparated string) Components {
	components := Components{}
	for _, compName := range strings.Split(commaSeparated, ",") {
		if component, exists := componentConverter[compName]; exists {
			components[component] = true
		} else {
			components[UnknownComponent] = true
		}
	}
	return components
}

// NewComponentsFromStringMap takes a string map (as used in PaasConfig) and converts it into a Components object
func NewComponentsFromStringMap(enabledComponents map[string]bool) Components {
	components := Components{}
	for compName, state := range enabledComponents {
		if component, exists := componentConverter[compName]; exists {
			components[component] = state
		} else {
			components[UnknownComponent] = state
		}
	}
	return components
}
