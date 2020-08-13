package constants

const (
	DatabaseURI         = "mongodb+srv://aisirotkin49:0gmtjytre@cluster0.oejju.gcp.mongodb.net/Auth?retryWrites=true&w=majority"
	DatabaseName        = "Auth"
	TokensCollection    = "Tokens"
	WriteConcernTimeout = 10
	ContextTimeout      = 10
	AccessTokenKey      = "access-token-key"
	RefreshTokenKey     = "refresh-token-key"
	MinGUIDLength       = 5
	CookieMaxAge        = 2592000
	CookiePath          = "/api/auth"
	CookieDomain        = ".localhost:9000."
	Error600            = "600. DB connection error"
	Error601            = "601. Transaction session start error"
	Error602            = "602. Delete error"
	Error604            = "604. Error in generating the hash of the refresh token"
	Error605            = "605. Error inserting a record into the database"
	Error606            = "606. User records search error"
	Error607            = "607. Parsing a record from the array in the variable error"
	Error608            = "608. Records pass error"
	Error609            = "609. Record was not found"
	Error610            = "610. Record deletion error"
	Error611            = "611. Record change error"
	Error612            = "612. Token generation error"
	Error613            = "613. Error reading GUID cookie"
	Error614            = "614. Invalid GUID"
	Error615            = "615. Error reading RefreshToken cookie"
	SuccessStatus       = "Success"
	ErrorStatus         = "Error"
)
