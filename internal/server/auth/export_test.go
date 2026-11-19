package auth

// HoldSlotForTest occupies one hashing slot and returns its release func.
func (s *Service) HoldSlotForTest() func() {
	s.slots <- struct{}{}
	return func() { <-s.slots }
}
