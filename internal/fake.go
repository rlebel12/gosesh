package internal

type FakeIdentifier struct {
	ID string
}

func (f *FakeIdentifier) String() string {
	return f.ID
}

func NewFakeIdentifier(id string) *FakeIdentifier {
	return &FakeIdentifier{ID: id}
}
