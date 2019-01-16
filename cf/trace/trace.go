package trace

import (
	. "code.cloudfoundry.org/cli/cf/i18n"
)

var LoggingToStdout bool

func Sanitize(input string) string {
	return input
}

func sanitizeJSON(propertySubstring string, json string) string {
	return json
}

func PrivateDataPlaceholder() string {
	return T("[PRIVATE DATA HIDDEN]")
}
