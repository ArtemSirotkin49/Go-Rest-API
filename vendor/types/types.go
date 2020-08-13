package types

type Tokens struct {
	AccessToken  string `bson:"accessToken" json:"accessToken,string"`
	RefreshToken string `bson:"refreshToken" json:"refreshToken,string"`
	GUID         string `bson:"GUID" json:"GUID,string"`
}
