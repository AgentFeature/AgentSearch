package hibp

// Breach is the allowlisted subset of HIBP's full breach model. Descriptions,
// logos and other unneeded remote content are not retained.
type Breach struct {
	Name         string   `json:"Name"`
	Title        string   `json:"Title"`
	Domain       string   `json:"Domain"`
	BreachDate   string   `json:"BreachDate"`
	AddedDate    string   `json:"AddedDate"`
	ModifiedDate string   `json:"ModifiedDate"`
	IsVerified   bool     `json:"IsVerified"`
	IsFabricated bool     `json:"IsFabricated"`
	DataClasses  []string `json:"DataClasses"`
}
