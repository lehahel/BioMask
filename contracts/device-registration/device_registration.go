package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"slices"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type DeviceRegistration struct {
	contractapi.Contract
}

// PhotoVote represents a vote on a set of photos
type PhotoVote struct {
	VoteId          string   `json:"voteId"`          // Unique identifier for the vote
	PhotoIPFSHashes []string `json:"photoIPFSHashes"` // IPFS hashes of the photos
	VoteCount       int      `json:"voteCount"`
	ValidVotes      int      `json:"validVotes"`
	InvalidVotes    int      `json:"invalidVotes"`
	Status          string   `json:"status"`          // "PENDING", "APPROVED", "REJECTED"
	Voters          []string `json:"voters"`          // List of voters who have already voted
	DevicePublicKey string   `json:"devicePublicKey"` // Public key hash of device being registered
}

// IPFSPhoto represents a photo stored in IPFS
type IPFSPhoto struct {
	IPFSHash    string `json:"ipfsHash"`
	Signature   string `json:"signature"`   // Digital signature of the photo
	UploadedBy  string `json:"uploadedBy"`  // Identity of the uploader
	TimeStamp   string `json:"timestamp"`   // Upload timestamp
	Description string `json:"description"` // Optional photo description
}

// DeviceKey represents a device's public key registration
type DeviceKey struct {
	PublicKeyHash string `json:"publicKeyHash"` // Hash of the public key for shorter reference
	PublicKey     string `json:"publicKey"`     // Full public key in PEM format
	Status        string `json:"status"`        // "UNVERIFIED" or "VERIFIED"
}

// verifyPhotoSignature validates the digital signature of a photo
func verifyPhotoSignature(photo IPFSPhoto, devicePublicKey string) bool {
	block, _ := pem.Decode([]byte(devicePublicKey))
	if block == nil {
		return false
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return false
	}

	message := photo.IPFSHash + photo.UploadedBy + photo.TimeStamp
	hashed := sha256.Sum256([]byte(message))

	sigBytes, err := hex.DecodeString(photo.Signature)
	if err != nil {
		return false
	}

	err = rsa.VerifyPSS(rsaPubKey, crypto.SHA256, hashed[:], sigBytes, nil)
	return err == nil
}

// StartPhotoVote initiates a new voting session for a set of IPFS photos
func (dr *DeviceRegistration) StartPhotoVote(ctx contractapi.TransactionContextInterface, ipfsPhotos []IPFSPhoto, devicePublicKey string) (*PhotoVote, error) {
	if len(ipfsPhotos) == 0 {
		return nil, fmt.Errorf("IPFS photos array cannot be empty")
	}

	// Get the identity of the caller
	// clientID, err := ctx.GetClientIdentity().GetID()
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to get client identity: %v", err)
	// }

	// Generate public key hash
	pubKeyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(devicePublicKey)))

	// Store device public key in unverified state
	deviceKey := DeviceKey{
		PublicKeyHash: pubKeyHash,
		PublicKey:     devicePublicKey,
		Status:        "UNVERIFIED",
	}
	deviceKeyJSON, err := json.Marshal(deviceKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal device key data: %v", err)
	}

	deviceKeyCompositeKey, err := ctx.GetStub().CreateCompositeKey("DeviceKey", []string{pubKeyHash})
	if err != nil {
		return nil, fmt.Errorf("failed to create composite key for device: %v", err)
	}

	err = ctx.GetStub().PutState(deviceKeyCompositeKey, deviceKeyJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to store device key: %v", err)
	}

	// Extract IPFS hashes and verify photos
	ipfsHashes := make([]string, len(ipfsPhotos))
	for i, photo := range ipfsPhotos {
		ipfsHashes[i] = photo.IPFSHash

		// Verify the uploader matches the transaction submitter
		// if photo.UploadedBy != clientID {
		// 	return nil, fmt.Errorf("photo uploader does not match transaction submitter %s != %s", photo.UploadedBy, clientID)
		// }

		// Verify digital signature
		if !verifyPhotoSignature(photo, devicePublicKey) {
			fmt.Println("Invalid digital signature for photo with hash: ", photo.IPFSHash)
			return nil, fmt.Errorf("invalid digital signature for photo with hash: %s", photo.IPFSHash)
		} else {
			fmt.Println("Valid digital signature for photo with hash: ", photo.IPFSHash)
		}

		// Store individual photo metadata
		photoKey, err := ctx.GetStub().CreateCompositeKey("Photo", []string{photo.IPFSHash})
		if err != nil {
			return nil, err
		}

		// Check if photo already exists
		existing, err := ctx.GetStub().GetState(photoKey)
		if err != nil {
			return nil, fmt.Errorf("failed to read from world state: %v", err)
		}
		if existing != nil {
			return nil, fmt.Errorf("photo with hash %s already exists", photo.IPFSHash)
		}

		photoJSON, err := json.Marshal(photo)
		if err != nil {
			return nil, err
		}

		err = ctx.GetStub().PutState(photoKey, photoJSON)
		if err != nil {
			return nil, err
		}
	}

	voteId := "vote-" + ipfsHashes[0] // Use first photo hash as ID instead of uuid
	// Create new vote record
	vote := PhotoVote{
		VoteId:          voteId,
		PhotoIPFSHashes: ipfsHashes,
		VoteCount:       0,
		ValidVotes:      0,
		InvalidVotes:    0,
		Status:          "PENDING",
		Voters:          make([]string, 0),
		DevicePublicKey: pubKeyHash,
	}

	// Convert to JSON
	voteJSON, err := json.Marshal(vote)
	if err != nil {
		return nil, err
	}

	// Create composite key using voteId as identifier
	voteKey, err := ctx.GetStub().CreateCompositeKey("PhotoVote", []string{voteId})
	if err != nil {
		return nil, err
	}
	fmt.Println("PUT voteKey '", voteKey, "'")

	// Store on blockchain
	err = ctx.GetStub().PutState(voteKey, voteJSON)
	if err != nil {
		return nil, err
	}
	return &vote, nil
}

// CastVote allows a participant to vote on photo validity
func (dr *DeviceRegistration) CastVote(ctx contractapi.TransactionContextInterface, voteId string, isValid bool) error {
	// Get vote key
	voteKey, err := ctx.GetStub().CreateCompositeKey("PhotoVote", []string{voteId})
	if err != nil {
		return err
	}

	// Get current vote state
	voteJSON, err := ctx.GetStub().GetState(voteKey)
	if err != nil {
		return err
	}
	if voteJSON == nil {
		return fmt.Errorf("vote for IPFS photo %s does not exist", voteId)
	}

	var vote PhotoVote
	err = json.Unmarshal(voteJSON, &vote)
	if err != nil {
		return err
	}

	// Check if vote is still pending
	if vote.Status != "PENDING" {
		return fmt.Errorf("voting for this photo set has ended")
	}

	// Get voter identity
	voterID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return err
	}

	// Check if voter has already voted
	if slices.Contains(vote.Voters, voterID) {
		return fmt.Errorf("voter has already cast a vote")
	}

	// Update vote counts
	vote.VoteCount++
	if isValid {
		vote.ValidVotes++
	} else {
		vote.InvalidVotes++
	}
	vote.Voters = append(vote.Voters, voterID)

	// Check if we have reached a consensus (simple majority for this example)
	if vote.VoteCount >= 1 { // Minimum 1 votes required
		if vote.ValidVotes > vote.InvalidVotes {
			vote.Status = "APPROVED"
			// Update device key status to VERIFIED using the hash stored in vote
			deviceKeyCompositeKey, err := ctx.GetStub().CreateCompositeKey("DeviceKey", []string{vote.DevicePublicKey})
			if err != nil {
				return fmt.Errorf("failed to create composite key for device: %v", err)
			}

			deviceKeyJSON, err := ctx.GetStub().GetState(deviceKeyCompositeKey)
			if err != nil {
				return fmt.Errorf("failed to get device key: %v", err)
			}

			var deviceKey DeviceKey
			err = json.Unmarshal(deviceKeyJSON, &deviceKey)
			if err != nil {
				return fmt.Errorf("failed to unmarshal device key: %v", err)
			}

			deviceKey.Status = "VERIFIED"
			updatedDeviceKeyJSON, err := json.Marshal(deviceKey)
			if err != nil {
				return fmt.Errorf("failed to marshal updated device key: %v", err)
			}

			err = ctx.GetStub().PutState(deviceKeyCompositeKey, updatedDeviceKeyJSON)
			if err != nil {
				return fmt.Errorf("failed to update device key status: %v", err)
			}
		}
	}

	// Store updated vote
	updatedVoteJSON, err := json.Marshal(vote)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(voteKey, updatedVoteJSON)
}

// GetVoteStatus returns the current status of a photo vote
func (dr *DeviceRegistration) GetVoteStatus(ctx contractapi.TransactionContextInterface, voteId string) (*PhotoVote, error) {
	voteKey, err := ctx.GetStub().CreateCompositeKey("PhotoVote", []string{voteId})
	if err != nil {
		return nil, err
	}
	fmt.Println("GET voteKey'", voteKey, "'")

	voteJSON, err := ctx.GetStub().GetState(voteKey)
	if err != nil {
		return nil, err
	}
	if voteJSON == nil {
		return nil, fmt.Errorf("vote for IPFS photo %s does not exist", voteId)
	}

	var vote PhotoVote
	err = json.Unmarshal(voteJSON, &vote)
	if err != nil {
		return nil, err
	}

	return &vote, nil
}

// GetPhotoMetadata returns the metadata for a specific photo
func (dr *DeviceRegistration) GetPhotoMetadata(ctx contractapi.TransactionContextInterface, ipfsHash string) (*IPFSPhoto, error) {
	photoKey, err := ctx.GetStub().CreateCompositeKey("Photo", []string{ipfsHash})
	if err != nil {
		return nil, err
	}

	photoJSON, err := ctx.GetStub().GetState(photoKey)
	if err != nil {
		return nil, err
	}
	if photoJSON == nil {
		return nil, fmt.Errorf("photo metadata for IPFS hash %s does not exist", ipfsHash)
	}

	var photo IPFSPhoto
	err = json.Unmarshal(photoJSON, &photo)
	if err != nil {
		return nil, err
	}

	return &photo, nil
}

// StoreHelperData stores helper data after verifying the signature with the device's public key
func (dr *DeviceRegistration) StoreHelperData(ctx contractapi.TransactionContextInterface, helper_data string, pub_key_hash string, signature string, nickname string) error {
	// Get device key from state
	deviceKeyCompositeKey, err := ctx.GetStub().CreateCompositeKey("DeviceKey", []string{pub_key_hash})
	if err != nil {
		return fmt.Errorf("failed to create composite key for device: %v", err)
	}

	deviceKeyJSON, err := ctx.GetStub().GetState(deviceKeyCompositeKey)
	if err != nil {
		return fmt.Errorf("failed to read device key from state: %v", err)
	}
	if deviceKeyJSON == nil {
		return fmt.Errorf("device key %s does not exist", pub_key_hash)
	}

	var deviceKey DeviceKey
	err = json.Unmarshal(deviceKeyJSON, &deviceKey)
	if err != nil {
		return fmt.Errorf("failed to unmarshal device key: %v", err)
	}

	// Verify signature
	block, _ := pem.Decode([]byte(deviceKey.PublicKey))
	if block == nil {
		return fmt.Errorf("failed to decode public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not RSA")
	}

	hashed := sha256.Sum256([]byte(helper_data))
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %v", err)
	}

	err = rsa.VerifyPSS(rsaPubKey, crypto.SHA256, hashed[:], sigBytes, nil)
	if err != nil {
		return fmt.Errorf("invalid signature")
	}

	// Store helper data using nickname as key
	helperDataKey, err := ctx.GetStub().CreateCompositeKey("HelperData", []string{nickname})
	if err != nil {
		return fmt.Errorf("failed to create composite key for helper data: %v", err)
	}

	err = ctx.GetStub().PutState(helperDataKey, []byte(helper_data))
	if err != nil {
		return fmt.Errorf("failed to store helper data: %v", err)
	}

	return nil
}

// GetHelperData retrieves helper data for a device from the world state
func (dr *DeviceRegistration) GetHelperData(ctx contractapi.TransactionContextInterface, nickname string) (string, error) {
	helperDataKey, err := ctx.GetStub().CreateCompositeKey("HelperData", []string{nickname})
	if err != nil {
		return "", fmt.Errorf("failed to create composite key for helper data: %v", err)
	}

	helperData, err := ctx.GetStub().GetState(helperDataKey)
	if err != nil {
		return "", fmt.Errorf("failed to read helper data from world state: %v", err)
	}
	if helperData == nil {
		return "", fmt.Errorf("helper data for nickname %s does not exist", nickname)
	}

	return string(helperData), nil
}

func main() {
	// Create a new instance of the simple contract
	contract := new(DeviceRegistration)

	// Create a new chaincode instance
	cc, err := contractapi.NewChaincode(contract)
	if err != nil {
		fmt.Printf("Error creating simple contract: %v", err)
		return
	}

	// Start the chaincode
	if err := cc.Start(); err != nil {
		fmt.Printf("Error starting simple contract: %v", err)
	}
}
