package transactions

import (
	"constants"
	"context"
	"errors"
	"strings"
	"time"
	"types"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/writeconcern"
	"golang.org/x/crypto/bcrypt"
)

// Transactions
func InsertTokensTransaction(accessToken, refreshToken, GUID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), constants.ContextTimeout*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(
		constants.DatabaseURI,
	))
	if err != nil {
		return errors.New(constants.Error600)
	}
	defer func() { client.Disconnect(ctx) }()
	wcMajority := writeconcern.New(writeconcern.WMajority(), writeconcern.WTimeout(constants.WriteConcernTimeout*time.Second))
	wcMajorityCollectionOpts := options.Collection().SetWriteConcern(wcMajority)
	tokensCollection := client.Database(constants.DatabaseName).Collection(constants.TokensCollection, wcMajorityCollectionOpts)

	callback := func(sessCtx mongo.SessionContext) (interface{}, error) {
		refreshTokenSignature := strings.Split(refreshToken, ".")[2]
		hashedRefreshTokenSignature, err := bcrypt.GenerateFromPassword([]byte(refreshTokenSignature), bcrypt.DefaultCost)
		if err != nil {
			return nil, errors.New(constants.Error604)
		}
		tokens := types.Tokens{accessToken, string(hashedRefreshTokenSignature), GUID}
		// Only the signatures of refresh tokens are DB, since the function "CompareHashAndPassword" can compare only first 72 bytes
		if _, err := tokensCollection.InsertOne(sessCtx, tokens); err != nil {
			return nil, errors.New(constants.Error605)
		}
		return nil, nil
	}

	session, err := client.StartSession()
	if err != nil {
		return errors.New(constants.Error601)
	}
	defer session.EndSession(ctx)

	if _, err := session.WithTransaction(ctx, callback); err != nil {
		return err
	}
	return nil
}

func RefreshTokensTransaction(newTokens types.Tokens, currentRefreshToken string) error {
	ctx, cancel := context.WithTimeout(context.Background(), constants.ContextTimeout*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(
		constants.DatabaseURI,
	))
	if err != nil {
		return errors.New(constants.Error600)
	}
	defer func() { client.Disconnect(ctx) }()

	wcMajority := writeconcern.New(writeconcern.WMajority(), writeconcern.WTimeout(constants.WriteConcernTimeout*time.Second))
	wcMajorityCollectionOpts := options.Collection().SetWriteConcern(wcMajority)
	tokensCollection := client.Database(constants.DatabaseName).Collection(constants.TokensCollection, wcMajorityCollectionOpts)

	callback := func(sessCtx mongo.SessionContext) (interface{}, error) {
		filter := bson.D{{"GUID", newTokens.GUID}}
		tokens, err := tokensCollection.Find(sessCtx, filter) //Array of token records
		if err != nil {
			return nil, errors.New(constants.Error606)
		}
		defer tokens.Close(ctx)

		currentRefreshTokenSignature := strings.Split(currentRefreshToken, ".")[2]
		for tokens.Next(ctx) {
			var token types.Tokens //One record from the array
			err := tokens.Decode(&token)
			if err != nil {
				return nil, errors.New(constants.Error607)
			}
			err = bcrypt.CompareHashAndPassword([]byte(token.RefreshToken), []byte(currentRefreshTokenSignature))
			// Only the signatures of refresh tokens are in DB, since the function can compare only first 72 bytes
			if err == nil {
				filter := bson.D{{"refreshToken", token.RefreshToken}, {"GUID", newTokens.GUID}}
				newRefreshTokenSignature := strings.Split(newTokens.RefreshToken, ".")[2]
				hashedNewRefreshTokenSignature, err := bcrypt.GenerateFromPassword([]byte(newRefreshTokenSignature), bcrypt.DefaultCost)
				if err != nil {
					panic(err)
				}
				newTokens.RefreshToken = string(hashedNewRefreshTokenSignature)
				if _, err := tokensCollection.UpdateOne(sessCtx, filter, bson.D{{"$set",
					bson.D{
						{"accessToken", newTokens.AccessToken},
						{"refreshToken", newTokens.RefreshToken},
					},
				}}); err != nil {
					return nil, errors.New(constants.Error611)
				}
				return nil, nil
			}
		}

		if err := tokens.Err(); err != nil {
			return nil, errors.New(constants.Error608)
		}
		return nil, errors.New(constants.Error609)
	}

	session, err := client.StartSession()
	if err != nil {
		return errors.New(constants.Error601)
	}
	defer session.EndSession(ctx)

	if _, err := session.WithTransaction(ctx, callback); err != nil {
		return err
	}
	return nil
}

func DeleteTokenTransaction(GUID, refreshToken string) error {
	ctx, cancel := context.WithTimeout(context.Background(), constants.ContextTimeout*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(
		constants.DatabaseURI,
	))
	if err != nil {
		return errors.New(constants.Error600)
	}
	defer func() { client.Disconnect(ctx) }()

	wcMajority := writeconcern.New(writeconcern.WMajority(), writeconcern.WTimeout(constants.WriteConcernTimeout*time.Second))
	wcMajorityCollectionOpts := options.Collection().SetWriteConcern(wcMajority)
	tokensCollection := client.Database(constants.DatabaseName).Collection(constants.TokensCollection, wcMajorityCollectionOpts)

	callback := func(sessCtx mongo.SessionContext) (interface{}, error) {
		filter := bson.D{{"GUID", GUID}}
		tokens, err := tokensCollection.Find(sessCtx, filter) //Array of token records
		if err != nil {
			return nil, errors.New(constants.Error606)
		}
		defer tokens.Close(ctx)

		for tokens.Next(ctx) {
			var token types.Tokens //One record from the array
			if err = tokens.Decode(&token); err != nil {
				return nil, errors.New(constants.Error607)
			}
			refreshTokenSignature := strings.Split(refreshToken, ".")[2]
			err = bcrypt.CompareHashAndPassword([]byte(token.RefreshToken), []byte(refreshTokenSignature)) // Compare signatures of refresh tokens
			// Only the signatures of refresh tokens are in DB, since the function can compare only first 72 bytes
			if err == nil {
				filter := bson.D{{"refreshToken", token.RefreshToken}, {"GUID", GUID}}
				if _, err := tokensCollection.DeleteOne(sessCtx, filter); err != nil {
					return nil, errors.New(constants.Error610)
				}
				return nil, nil
			}
		}
		if err := tokens.Err(); err != nil {
			return nil, errors.New(constants.Error608)
		}
		return nil, errors.New(constants.Error609)
	}

	session, err := client.StartSession()
	if err != nil {
		return errors.New(constants.Error601)
	}
	defer session.EndSession(ctx)

	if _, err := session.WithTransaction(ctx, callback); err != nil {
		return err
	}
	return nil
}

func DeleteAllTokensTransaction(GUID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), constants.ContextTimeout*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(
		constants.DatabaseURI,
	))
	if err != nil {
		return errors.New(constants.Error600)
	}
	defer func() { client.Disconnect(ctx) }()

	wcMajority := writeconcern.New(writeconcern.WMajority(), writeconcern.WTimeout(constants.WriteConcernTimeout*time.Second))
	wcMajorityCollectionOpts := options.Collection().SetWriteConcern(wcMajority)
	tokensCollection := client.Database(constants.DatabaseName).Collection(constants.TokensCollection, wcMajorityCollectionOpts)

	callback := func(sessCtx mongo.SessionContext) (interface{}, error) {
		filter := bson.D{{"GUID", GUID}}
		if _, err := tokensCollection.DeleteMany(sessCtx, filter); err != nil {
			return nil, errors.New(constants.Error602)
		}
		return nil, nil
	}

	session, err := client.StartSession()
	if err != nil {
		return errors.New(constants.Error601)
	}
	defer session.EndSession(ctx)

	if _, err := session.WithTransaction(ctx, callback); err != nil {
		return err
	}
	return nil
}
