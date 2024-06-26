package betty

// BadPractice exports functions which are generally considered bad practice.
// These functions are only provided for backwards compatibility with legacy systems,
// modern transparency ecosystems should not use them.
var BadPractice *badPractice

type badPractice struct{}

// WithLeafHash is a NewEntry option which overrides an entry's MerkleLeafHash.
//
// Normally, this should be calculated automatically and commit to the entirety of the
// leaf data. Overriding this can result in anything from a tree with entries which
// cannot shown to have been included, to broken security properties due to malleable
// entries.
func (b badPractice) WithLeafHash(leafHash []byte) EntryOpt {
	return func(e *Entry) {
		e.leafHash = leafHash
	}
}
