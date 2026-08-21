package iam

import (
	"net/mail"
	"regexp"
	"strings"
)

var createLocalUserUsernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)

// validateCreateLocalUserCommand accepts only canonical management input. It
// deliberately does not normalize user-supplied values so HTTP and internal
// callers observe the same predictable contract.
func validateCreateLocalUserCommand(command CreateLocalUserCommand) (CreateLocalUserCommand, error) {
	if strings.TrimSpace(command.Username) != command.Username || strings.ToLower(command.Username) != command.Username || !createLocalUserUsernamePattern.MatchString(command.Username) {
		return CreateLocalUserCommand{}, ErrUserInputInvalid
	}
	if command.DisplayName == "" || strings.TrimSpace(command.DisplayName) != command.DisplayName || len([]rune(command.DisplayName)) > 256 {
		return CreateLocalUserCommand{}, ErrUserInputInvalid
	}
	if command.Email == "" {
		return command, nil
	}
	if strings.TrimSpace(command.Email) != command.Email || strings.ToLower(command.Email) != command.Email || len([]rune(command.Email)) > 320 {
		return CreateLocalUserCommand{}, ErrUserInputInvalid
	}
	address, err := mail.ParseAddress(command.Email)
	if err != nil || address.Address != command.Email {
		return CreateLocalUserCommand{}, ErrUserInputInvalid
	}
	return command, nil
}
