package auth

// HoldSlotForTest occupies one hashing slot and returns its release func.
func (s *Service) HoldSlotForTest() func() {
	s.slots <- struct{}{}
	return func() { <-s.slots }
}

// VerifyPasswordForTest exposes verifyPassword.
func VerifyPasswordForTest(password, encoded string) bool { return verifyPassword(password, encoded) }

// HashPasswordForTest exposes hashPassword.
func HashPasswordForTest(password string) (string, error) { return hashPassword(password) }
