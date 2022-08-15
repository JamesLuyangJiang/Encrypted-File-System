package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	//"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	"strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username   string
	RootKey    []byte                 // root key of the user to generate other keys
	PrivateKey userlib.PrivateKeyType // private key used to decrypt invitations
	UserFiles  map[string]FileInfo    // Map filenames to fileInfo
	password   string

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type FileInfo struct {
	FileName string
	Owner    string // Owner of the file
	Sender   string
	Version  int // Amount of times of key update
}

type Header struct {
	FileName string
	Owner    string // Owner of the file
	Version  int
	BlockNum int        // Total number of blocks the file have
	Tree     [][]string // List of lists of usernames have been shared with this file
	Test     string
}

type File struct {
	Content []byte // Plaintext of the file contents
}

type Invitation struct {
	UUID        uuid.UUID // UUID of the file
	RootFileKey []byte    // Root key of the file
	Version     int       // Version of the file due to revoke access
}

type EncInvitation struct {
	CipherA []byte
	CipherB []byte
	SigA    []byte
	SigB    []byte
}

func UpdateUser(userData User) (userdataptr *User, err error) {
	/* Sync the user status to avoid mutable state not present in
	multiple sessions for the same username */

	// Load User attributes
	username := userData.Username
	password := userData.password
	// Derive the ENC key
	encKey, err := userlib.HashKDF(userData.RootKey, []byte("ENC"))
	if err != nil {
		return nil, err
	}
	// Derive the MAC key
	macKey, err := userlib.HashKDF(userData.RootKey, []byte("MAC"))
	if err != nil {
		return nil, err
	}
	// Obtain an encrypted copy of the user data
	iv := userlib.RandomBytes(16)
	plainText, err := json.Marshal(userData)
	if err != nil {
		return nil, err
	}
	encUser := userlib.SymEnc(encKey[:16], iv, plainText)

	// Obtain the HMAC for this data
	mac, err := userlib.HMACEval(macKey[:16], encUser)
	if err != nil {
		return nil, err
	}

	// Generate UUID
	hash := userlib.Hash([]byte(username))
	userUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return nil, err
	}
	dataEntry, exist := userlib.DatastoreGet(userUUID)
	if !exist {
		return nil, errors.New("user does not exist")
	}
	salt := dataEntry[:16]

	// Parse the data entry byte slice
	dataEntry = salt
	dataEntry = append(dataEntry, mac...)
	dataEntry = append(dataEntry, encUser...)

	// Set the information in the datastore and return
	userlib.DatastoreSet(userUUID, dataEntry)
	return GetUser(username, password)

}

func InitUser(username string, password string) (userdataptr *User, err error) {
	/* Initialize the user with the provided login information, returns
	a pointer to the struct */

	// Generate a base username with default attributes
	var userData User
	userData.Username = username
	userData.UserFiles = map[string]FileInfo{}

	// Check empty username error
	if len(username) == 0 {
		return nil, errors.New("empty username")
	}

	// Generate UUID
	hash := userlib.Hash([]byte(username))
	userUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return nil, err
	}

	// Check existing same name user error
	_, exist := userlib.DatastoreGet(userUUID)
	if exist {
		return nil, errors.New("same username exist")
	}

	// Derive encryption and MAC keys
	salt := userlib.RandomBytes(16)
	userData.RootKey = userlib.Argon2Key([]byte(password), salt, 16)
	encKey, err := userlib.HashKDF(userData.RootKey, []byte("ENC"))
	if err != nil {
		return nil, err
	}
	macKey, err := userlib.HashKDF(userData.RootKey, []byte("MAC"))
	if err != nil {
		return nil, err
	}

	// Derive and store public and private keys
	publicKey, privateKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	userData.PrivateKey = privateKey
	userlib.KeystoreSet(username, publicKey)

	// Obtain the encrypted user information
	iv := userlib.RandomBytes(16)
	plainText, err := json.Marshal(userData)
	if err != nil {
		return nil, err
	}
	encUser := userlib.SymEnc(encKey[:16], iv, plainText)

	// Obtain the HMAC for this data
	mac, err := userlib.HMACEval(macKey[:16], encUser)
	if err != nil {
		return nil, err
	}

	// Obtain the data entry
	dataEntry := salt
	dataEntry = append(dataEntry, mac...)
	dataEntry = append(dataEntry, encUser...)

	// Set the user data and return
	userlib.DatastoreSet(userUUID, dataEntry)
	return GetUser(username, password)
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	/* Get a user pointer from an already existing user
	in the datastore */

	// Generate a base user struct
	var userData User
	userData.password = password

	// Generate UUID
	hash := userlib.Hash([]byte(username))
	userUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return nil, err
	}

	// Obtain MAC and salt from dataentry
	dataEntry, exist := userlib.DatastoreGet(userUUID)
	if !exist {
		return nil, errors.New("user does not exist")
	}
	salt := dataEntry[:16]
	mac := dataEntry[16:80]

	// Regenerate rootkey
	rootKey := userlib.Argon2Key([]byte(password), salt, 16)

	// Derive Mac key
	macKey, err := userlib.HashKDF(rootKey, []byte("MAC"))
	if err != nil {
		return nil, err
	}

	// Generate new Mac
	newMac, err := userlib.HMACEval(macKey[:16], dataEntry[80:])
	if err != nil {
		return nil, err
	}

	// Check invalid password or malicious action error
	equal := userlib.HMACEqual(newMac, mac)
	if !equal {
		return nil, errors.New("invalid user credentials or detected malicious actions")
	}

	// Obtain decryption key and decrypt content
	decKey, err := userlib.HashKDF(rootKey, []byte("ENC"))
	if err != nil {
		return nil, err
	}
	plainText := userlib.SymDec(decKey[:16], dataEntry[80:])
	err = json.Unmarshal(plainText, &userData)
	if err != nil {
		return nil, err
	}

	// Set pointer to generated user data and return
	userdataptr = &userData
	return userdataptr, nil
}

func james(root []byte, content []byte, enc string, mac string) (out []byte, err error) {
	/* Get the encrypted version of a content and mac in a single byte
	slice from a root key */

	// Derive a key for Encryption
	encKey, err := userlib.HashKDF(root[:16], []byte(enc))
	if err != nil {
		return nil, err
	}

	// Derive a key for MAC
	macKey, err := userlib.HashKDF(root[:16], []byte(mac))
	if err != nil {
		return nil, err
	}

	// Encrypt and MAC content
	encContent := userlib.SymEnc(encKey[:16], userlib.RandomBytes(16), content)
	macContent, err := userlib.HMACEval(macKey[:16], encContent)
	if err != nil {
		return nil, err
	}

	// Return the complete byte slice in the form of mac | enc
	output := macContent
	output = append(output, encContent...)
	return output, nil
}

func unjames(root []byte, content []byte, enc string, mac string) (out []byte, err error) {
	/* Revert the james output, from a byte slice uncencrypt and confirm
	mac matches, output plaintext content */

	// First 64 bytes is the mac, everything else is the encrypted content
	recievedMac := content[:64]
	recievedEnc := content[64:]

	// Derive keys from encryption and mac
	encKey, err := userlib.HashKDF(root[:16], []byte(enc))
	if err != nil {
		return nil, err
	}
	macKey, err := userlib.HashKDF(root[:16], []byte(mac))
	if err != nil {
		return nil, err
	}

	// Mac the encryption
	generatedMac, err := userlib.HMACEval(macKey[:16], recievedEnc)
	if err != nil {
		return nil, err
	}

	// If the generated mac matches the recieved mac
	if userlib.HMACEqual(recievedMac, generatedMac) {
		// Unencrypt the content
		unEncContent := userlib.SymDec(encKey[:16], recievedEnc)
		return unEncContent, nil
	} else {
		return []byte(""), errors.New("macs do not match.")
	}
}

func GetFileEverything(userdata *User, filename string) (header Header, fileRootKey []byte, fileInfo FileInfo, err error) {
	/* Helper function to obtain everything from a file, regardless if the user
	is the owner or not */

	// If the file exists inside the user space
	if fileInfo, check := userdata.UserFiles[filename]; check {
		fileRootKey := []byte("")

		// If the user is the owner
		if fileInfo.Owner == userdata.Username {

			// Determinsitcally derive a root key
			purpose := fmt.Sprintf("%s%s%d", fileInfo.Owner, fileInfo.FileName, fileInfo.Version)
			fileRoot, err := userlib.HashKDF(userdata.RootKey, []byte(purpose))
			if err != nil {
				return header, fileRootKey, fileInfo, err
			}
			fileRootKey = fileRoot
			// If the user is not the owner
		} else {
			// Check the invitation for the root key
			_, fileRoot, version, err := userdata.AccessInvitation(fileInfo)
			if err != nil {
				return header, fileRootKey, fileInfo, err
			}
			fileRootKey = fileRoot
			fileInfo.Version = version
		}

		// Generate the header uuid
		uuidString := fmt.Sprintf("%s%s%d", fileInfo.Owner, fileInfo.FileName, fileInfo.Version)
		hash := userlib.Hash([]byte(uuidString))
		headerUUID, err := uuid.FromBytes(hash[:16])
		if err != nil {
			return header, fileRootKey, fileInfo, err
		}

		// Obtain the header content
		headerEncContent, ok := userlib.DatastoreGet(headerUUID)
		if !ok {
			return header, fileRootKey, fileInfo, errors.New("no element in datastore")
		}
		unencryptedHeader, err := unjames(fileRootKey, headerEncContent, "ENC", "MAC")
		if err != nil {
			return header, fileRootKey, fileInfo, err
		}
		err = json.Unmarshal(unencryptedHeader, &header)
		if err != nil {
			return header, fileRootKey, fileInfo, err
		}

		// If everything is obtained, return all the file information
		return header, fileRootKey, fileInfo, nil
	} else {
		return header, fileRootKey, fileInfo, errors.New("load file errors, no file found")
	}
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	/* Stores a file inside the user's namespace, only returns
	an error in case anything fails */

	// Update the user data
	userdata, err = GetUser(userdata.Username, userdata.password)
	if err != nil {
		return err
	}

	// If the file exists, we remove everything that exists
	if _, check := userdata.UserFiles[filename]; check {

		// Delete the old header and file blocks from DataStore
		header, fileRootKey, fileInfo, err := GetFileEverything(userdata, filename)
		if err != nil {
			return err
		}
		oldBlockNum := header.BlockNum

		// Get header uuid
		uuidString := fmt.Sprintf("%s%s%d", header.Owner, header.FileName, fileInfo.Version)
		hash := userlib.Hash([]byte(uuidString))
		headerUUID, err := uuid.FromBytes(hash[:16])
		if err != nil {
			return err
		}

		// Delete header
		userlib.DatastoreDelete(headerUUID)

		for i := 1; i <= oldBlockNum; i++ {
			// Generate the file block UUID
			uuidString := fmt.Sprintf("%s%s%d%d", header.Owner, header.FileName, fileInfo.Version-1, i)
			hash := userlib.Hash([]byte(uuidString))
			blockUUID, err := uuid.FromBytes(hash[:16])
			if err != nil {
				return err
			}
			// Delete block
			userlib.DatastoreDelete(blockUUID)
		}

		// Now that the previous file is deleted, we can store the new one

		// Get file contents
		headerMarshal, err := json.Marshal(header)
		if err != nil {
			return err
		}
		storageContent, err := james(fileRootKey, headerMarshal, "ENC", "MAC")
		if err != nil {
			return err
		}

		// e. A $$UUID_{header}$$  is generated from the string username | filename | version.
		uuidString = fmt.Sprintf("%s%s%d", fileInfo.Owner, header.FileName, header.Version)
		hash = userlib.Hash([]byte(uuidString))
		headerUUID, err = uuid.FromBytes(hash[:16])
		if err != nil {
			return err
		}
		userlib.DatastoreSet(headerUUID, storageContent)

		// f. The MAC and encrypted Header will be stored through DataStore at $$UUID_{header}$$.
		storageKey, err := uuid.FromBytes(userlib.Hash([]byte(header.FileName + fileInfo.Owner))[:16])
		if err != nil {
			return err
		}
		contentBytes, err := json.Marshal(content)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(storageKey, contentBytes)

		// g. Derive 2 keys from $$SK_{FILEROOT}$$ using HashKDF with "ENC" | ChunkNum + 1 "MAC" | ChunkNum + 1 as purposes.
		// h. Use the new keys to encrypt the file struct and generate the MAC, note that there is only one chunk, so everytime we call ChunkNum + 1 in this section we are noting 0 + 1. The ChunkNum syntax is used for correctness and will be usefull when appending content.
		storageContent, err = james(fileRootKey, content, "ENC-1", "MAC-1")
		if err != nil {
			return err
		}

		// i. A $$UUID_{file}$$ is generated from the string username | filename | version | BlockNum + 1
		uuidString = fmt.Sprintf("%s%s%d%d", fileInfo.Owner, header.FileName, header.Version, 1)
		hash = userlib.Hash([]byte(uuidString))
		fileUUID, err := uuid.FromBytes(hash[:16])
		if err != nil {
			return err
		}

		// j. The encrypted file and the MAC will be stored at the $$UUID_{file}$$.
		userlib.DatastoreSet(fileUUID, storageContent)

		// // k. Generate a booklet containing the information of the file and storing both $$SK_{headerEnc}$$ and $$SK_{headerMac}$$.
		// var info FileInfo
		// info.FileName = filename
		// info.Owner = userdata.Username
		// info.Version = 0

		// // l. Add the booklet into the UserFiles dictionary, with the filename as the key.
		// userdata.UserFiles[filename] = info
		UpdateUser(*userdata)

	} else {
		var header Header
		header.BlockNum = 1
		header.Version = 0
		header.Owner = userdata.Username
		header.FileName = filename

		// b. A File instance is generated with the file’s content, filename, owner , version which defaults to 0.
		// c. The root key of the file $$SK_{FILEROOT}$$ is derived from the user’s $$SK_{ROOT}$$ using HashKDF with username | filename | version as purpose.
		purpose := fmt.Sprintf("%s%s%d", userdata.Username, filename, header.Version)
		fileRootKey, err := userlib.HashKDF(userdata.RootKey, []byte(purpose))
		if err != nil {
			return err
		}

		// d. The encrypted Header and related MAC will be returned from the helper function James:
		headerMarshal, err := json.Marshal(header)
		if err != nil {
			return err
		}
		storageContent, err := james(fileRootKey, headerMarshal, "ENC", "MAC")
		if err != nil {
			return err
		}

		// e. A $$UUID_{header}$$  is generated from the string username | filename | version.
		uuidString := fmt.Sprintf("%s%s%d", userdata.Username, filename, header.Version)
		hash := userlib.Hash([]byte(uuidString))
		headerUUID, err := uuid.FromBytes(hash[:16])
		if err != nil {
			return err
		}
		userlib.DatastoreSet(headerUUID, storageContent)

		// f. The MAC and encrypted Header will be stored through DataStore at $$UUID_{header}$$.
		storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
		if err != nil {
			return err
		}
		contentBytes, err := json.Marshal(content)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(storageKey, contentBytes)

		// g. Derive 2 keys from $$SK_{FILEROOT}$$ using HashKDF with "ENC" | ChunkNum + 1 "MAC" | ChunkNum + 1 as purposes.
		// h. Use the new keys to encrypt the file struct and generate the MAC, note that there is only one chunk, so everytime we call ChunkNum + 1 in this section we are noting 0 + 1. The ChunkNum syntax is used for correctness and will be usefull when appending content.
		storageContent, err = james(fileRootKey, content, "ENC-1", "MAC-1")
		if err != nil {
			return err
		}

		// i. A $$UUID_{file}$$ is generated from the string username | filename | version | BlockNum + 1
		uuidString = fmt.Sprintf("%s%s%d%d", userdata.Username, filename, header.Version, 1)
		hash = userlib.Hash([]byte(uuidString))
		fileUUID, err := uuid.FromBytes(hash[:16])
		if err != nil {
			return err
		}

		// j. The encrypted file and the MAC will be stored at the $$UUID_{file}$$.
		userlib.DatastoreSet(fileUUID, storageContent)

		// k. Generate a booklet containing the information of the file and storing both $$SK_{headerEnc}$$ and $$SK_{headerMac}$$.
		var info FileInfo
		info.FileName = filename
		info.Owner = userdata.Username
		info.Version = 0

		// l. Add the booklet into the UserFiles dictionary, with the filename as the key.
		userdata.UserFiles[filename] = info
		UpdateUser(*userdata)
	}
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	/* Lodas a file inside the user namespace, returns the unencrypted
	content or error if it does not exist */

	// Update the user data
	userdata, err = GetUser(userdata.Username, userdata.password)
	if err != nil {
		return nil, err
	}

	// Obtain all the file information
	header, fileRootKey, fileInfo, err := GetFileEverything(userdata, filename)
	if err != nil {
		return nil, err
	}

	// Read the content from every chunk
	var completeContent []byte
	for chunk_n := 1; chunk_n <= header.BlockNum; chunk_n += 1 {

		// Get the uuid for this chunk in datastore
		uuidString := fmt.Sprintf("%s%s%d%d", fileInfo.Owner, fileInfo.FileName, fileInfo.Version, chunk_n)
		hash := userlib.Hash([]byte(uuidString))
		headerUUID, err := uuid.FromBytes(hash[:16])
		if err != nil {
			return nil, err
		}

		// Unencrypt the content
		headerEncContent, ok := userlib.DatastoreGet(headerUUID)
		if !ok {
			return nil, err
		}
		encPurpose := fmt.Sprintf("ENC-%d", chunk_n)
		macPurpose := fmt.Sprintf("MAC-%d", chunk_n)
		storageContent, err := unjames(fileRootKey, headerEncContent, encPurpose, macPurpose)
		if err != nil {
			return nil, err
		}

		// Append the content of this chunk to the total content
		completeContent = append(completeContent, storageContent...)
	}

	// When all chunks are read, return the complete content
	return completeContent, nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	/* Efficiently append content to a file, only reading the header (constant size),
	and creating a chunk at the end */

	// Update the user data
	userdata, err := GetUser(userdata.Username, userdata.password)
	if err != nil {
		return err
	}

	// Obtain all the file information
	header, fileRootKey, fileInfo, err := GetFileEverything(userdata, filename)
	if err != nil {
		return err
	}

	// Load and update header to recognize the new chunk
	header.BlockNum += 1
	headerMarshal, err := json.Marshal(header)
	if err != nil {
		return err
	}
	storageContent, err := james(fileRootKey, headerMarshal, "ENC", "MAC")
	if err != nil {
		return err
	}
	uuidString := fmt.Sprintf("%s%s%d", fileInfo.Owner, fileInfo.FileName, header.Version)
	hash := userlib.Hash([]byte(uuidString))
	headerUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return err
	}
	userlib.DatastoreSet(headerUUID, storageContent)

	// Generate needed purposes to james the new content
	encPurpose := fmt.Sprintf("ENC-%d", header.BlockNum)
	macPurpose := fmt.Sprintf("MAC-%d", header.BlockNum)
	storageContent, err = james(fileRootKey, content, encPurpose, macPurpose)

	// A UUID_{file} is generated from the string username | filename | version | BlockNum + 1
	uuidString = fmt.Sprintf("%s%s%d%d", fileInfo.Owner, fileInfo.FileName, header.Version, header.BlockNum)
	hash = userlib.Hash([]byte(uuidString))
	fileUUID, err := uuid.FromBytes(hash[:16])

	// The encrypted file and the MAC will be stored at the UUID_{file}.
	userlib.DatastoreSet(fileUUID, storageContent)

	// If no error is present, return nil
	return nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	/* Creates an invitation and sets encrypted information in the
	   datastore, to be later retrieved by invited user */

	// Generate basic invitation information
	var invitationUUID uuid.UUID
	var invitation Invitation
	var fileRoot []byte

	// Get the latest user struct from DataStore
	userdata, err = GetUser(userdata.Username, userdata.password)
	if err != nil {
		return invitationUUID, err
	}

	// Check for filename is not in user's namespace error
	fileInfo, exist := userdata.UserFiles[filename]
	if !exist {
		return invitationUUID, errors.New("file does not exist")
	}

	// Case of sender is not the owner
	if fileInfo.Owner != userdata.Username {
		_, fileRoot, fileInfo.Version, err = userdata.AccessInvitation(fileInfo)
		if err != nil {
			return invitationUUID, err
		}
	} else { // Case of sender is the owner
		fileRoot, err = userlib.HashKDF(userdata.RootKey, []byte(userdata.Username+filename+strconv.FormatInt(int64(fileInfo.Version), 10)))
		if err != nil {
			return invitationUUID, err
		}
	}

	// Get recipient's public key, check recipient does not exist error
	publicKey, exist := userlib.KeystoreGet(recipientUsername)
	if !exist {
		return invitationUUID, errors.New("recipient does not exist")
	}

	// Generate the UUID of the file
	hash := userlib.Hash([]byte(fileInfo.Owner + fileInfo.FileName + strconv.FormatInt(int64(fileInfo.Version), 10)))
	fileUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return invitationUUID, err
	}

	// Get file header and check for revoke error
	dataEntry, exist := userlib.DatastoreGet(fileUUID)
	if !exist {
		return invitationUUID, errors.New("invitation revoked")
	}

	// Decrypt the header
	plainHeader, err := unjames(fileRoot, dataEntry, "ENC", "MAC")
	if err != nil {
		return invitationUUID, err
	}

	// Unmarshal the header
	var header Header
	err = json.Unmarshal(plainHeader, &header)
	if err != nil {
		return invitationUUID, err
	}

	// Update the tree list in header
	if fileInfo.Owner != userdata.Username {
		for i, branch := range header.Tree {
			if branch[0] == userdata.Username {
				header.Tree[i] = append(header.Tree[i], recipientUsername)
			}
		}
	} else {
		newSlice := []string{recipientUsername}
		header.Tree = append(header.Tree, newSlice)
	}

	// Marshal the header
	plainHeader, err = json.Marshal(header)
	if err != nil {
		return invitationUUID, err
	}

	// Generate the Enc and MAC of the header
	encHeader, err := james(fileRoot, plainHeader, "ENC", "MAC")
	if err != nil {
		return invitationUUID, err
	}

	// Update the header
	userlib.DatastoreDelete(fileUUID)
	userlib.DatastoreSet(fileUUID, encHeader)

	// Construct invitation
	invitation.UUID = fileUUID
	invitation.RootFileKey = fileRoot
	invitation.Version = fileInfo.Version

	// Marshal invitation
	plainText, err := json.Marshal(invitation)
	if err != nil {
		return invitationUUID, err
	}

	// Genearate invitation and UUID, and store the invitation
	invitationDataEntry, err := encInvite(plainText, publicKey, userdata.PrivateKey)
	if err != nil {
		return invitationUUID, err
	}

	inviteUUID, err := uuid.FromBytes(userlib.Hash([]byte(fileInfo.FileName + fileInfo.Owner + recipientUsername))[:16])
	if err != nil {
		return invitationUUID, err
	}

	userlib.DatastoreSet(inviteUUID, invitationDataEntry)

	return inviteUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	/* Accept an invitation from another user, and save file into
	personal userspace file information map */

	// Get the latest user struct from DataStore
	userdata, err := GetUser(userdata.Username, userdata.password)
	if err != nil {
		return err
	}

	// Get the invitation from DataStore
	dataEntry, exist := userlib.DatastoreGet(invitationPtr)
	if !exist {
		return errors.New("invitation does not exist")
	}

	// Get sender's pk to verify signature
	publicKey, exist := userlib.KeystoreGet(senderUsername)
	if !exist {
		return errors.New("cannot verify the invitation")
	}

	// Get marshlled invitation
	plainText, err := decInvite(dataEntry, publicKey, userdata.PrivateKey)
	if err != nil {
		return err
	}

	// Unmarshal the inviation
	var invitation Invitation
	err = json.Unmarshal(plainText, &invitation)
	if err != nil {
		return err
	}

	// Get file header and check for revoke error
	cipherHeader, exist := userlib.DatastoreGet(invitation.UUID)
	if !exist {
		return errors.New("invitation revoked")
	}

	// Decrypt the header
	plainHeader, err := unjames(invitation.RootFileKey, cipherHeader, "ENC", "MAC")
	if err != nil {
		return err
	}

	// Unmarshal the header
	var header Header
	err = json.Unmarshal(plainHeader, &header)
	if err != nil {
		return err
	}

	// Check for same filename is in receiver's namespace error
	_, found := userdata.UserFiles[filename]
	if found {
		return errors.New("same file name already exist")
	}

	// Create the new fileInfo entry in the receiver's namespace
	var fileInfo FileInfo
	fileInfo.FileName = header.FileName
	fileInfo.Owner = header.Owner
	fileInfo.Version = header.Version
	fileInfo.Sender = senderUsername

	userdata.UserFiles[filename] = fileInfo
	UpdateUser(*userdata)
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	/* Revokes the acces of a directly shared user, or its children and re-encrypts
	the file contents into a single chunk */

	// Get the latest user struct from DataStore
	userdata, err := GetUser(userdata.Username, userdata.password)
	if err != nil {
		return err
	}

	// Check for filename is not in user's namespace error
	fileInfo, exist := userdata.UserFiles[filename]
	if !exist {
		return errors.New("file does not exist")
	}

	// Check for if shared with the recipient or not
	uuidStr := fmt.Sprintf("%s%s%s", filename, userdata.UserFiles[filename].Owner, recipientUsername)
	inviteHash := userlib.Hash([]byte(uuidStr))
	invitUUID, err := uuid.FromBytes(inviteHash[:16])
	if err != nil {
		return err
	}

	_, exist = userlib.DatastoreGet(invitUUID)
	if !exist {
		return errors.New("did not share file to the receiver before")
	}

	// Regenerate old file root key
	fileString := fmt.Sprintf("%s%s%d", userdata.Username, filename, fileInfo.Version)
	fileRoot, err := userlib.HashKDF(userdata.RootKey, []byte(fileString))
	if err != nil {
		return err
	}

	// Get the file content
	fileContent, err := userdata.LoadFile(filename)
	if err != nil {
		return err
	}

	// Generate the header UUID
	uuidString := fmt.Sprintf("%s%s%d", userdata.Username, filename, fileInfo.Version)
	hash := userlib.Hash([]byte(uuidString))
	headerUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return err
	}

	// Get encrypted header
	headerEncContent, ok := userlib.DatastoreGet(headerUUID)
	if !ok {
		return errors.New("file does not exist")
	}

	// Decrypt the header
	unencryptedHeader, err := unjames(fileRoot, headerEncContent, "ENC", "MAC")
	if err != nil {
		return err
	}

	// Unmarshal the header
	var header Header
	err = json.Unmarshal(unencryptedHeader, &header)
	if err != nil {
		return err
	}

	// Update the header
	oldBlockNum := header.BlockNum
	header.BlockNum = 1
	header.Version += 1

	// Update the tree slice in header, deleting that branch of revoked users
	for i, val := range header.Tree {
		if val[0] == recipientUsername {
			header.Tree[i] = header.Tree[len(header.Tree)-1]
			header.Tree = header.Tree[:len(header.Tree)-1]
			break
		}
	}

	// Generate the new file rootkey
	fileString = fmt.Sprintf("%s%s%d", userdata.Username, filename, fileInfo.Version+1)
	newFileRootKey, err := userlib.HashKDF(userdata.RootKey, []byte(fileString))
	if err != nil {
		return err
	}

	fileInfo.Version += 1
	userdata.UserFiles[filename] = fileInfo

	plainText, err := json.Marshal(header)
	if err != nil {
		return err
	}

	// Encrypt the header and file content with new key
	encHeader, err := james(newFileRootKey, plainText, "ENC", "MAC")
	if err != nil {
		return err
	}

	encFile, err := james(newFileRootKey, fileContent, "ENC-1", "MAC-1")
	if err != nil {
		return err
	}

	// Generate the new header UUID
	uuidString = fmt.Sprintf("%s%s%d", userdata.Username, filename, fileInfo.Version)
	hash = userlib.Hash([]byte(uuidString))
	newHeaderUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return err
	}

	// Generate the new file UUID
	uuidString = fmt.Sprintf("%s%s%d%d", userdata.Username, filename, fileInfo.Version, 1)
	hash = userlib.Hash([]byte(uuidString))
	fileUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return err
	}

	// Delete the old header and file blocks from DataStore
	userlib.DatastoreDelete(headerUUID)

	for i := 1; i <= oldBlockNum; i++ {
		// Generate the file block UUID
		uuidString = fmt.Sprintf("%s%s%d%d", userdata.Username, filename, fileInfo.Version-1, i)
		hash = userlib.Hash([]byte(uuidString))
		blockUUID, err := uuid.FromBytes(hash[:16])
		if err != nil {
			return err
		}

		userlib.DatastoreDelete(blockUUID)
	}

	// Store the new header and content at new place
	userlib.DatastoreSet(newHeaderUUID, encHeader)
	userlib.DatastoreSet(fileUUID, encFile)

	// Go through the saved old tree, update the invitations
	for _, branch := range header.Tree {
		for _, receiver := range branch {
			// Generate UUID for the invitation, and clear old invitation
			inviteUUID, err := uuid.FromBytes(userlib.Hash([]byte(fileInfo.FileName + fileInfo.Owner + receiver))[:16])
			if err != nil {
				return err
			}

			userlib.DatastoreDelete(inviteUUID)

			// Construct the new invitation
			var invitation Invitation
			invitation.UUID = newHeaderUUID
			invitation.RootFileKey = newFileRootKey
			invitation.Version = fileInfo.Version

			// Marshal invitation
			plainText, err := json.Marshal(invitation)
			if err != nil {
				return err
			}

			// Get receiver's pk for encryption
			publicKey, exist := userlib.KeystoreGet(receiver)
			if !exist {
				return errors.New("cannot get receiver's public key during updating invitation")
			}

			// Store the new invitation
			invitationDataEntry, err := encInvite(plainText, publicKey, userdata.PrivateKey)
			if err != nil {
				return err
			}

			userlib.DatastoreSet(inviteUUID, invitationDataEntry)
		}
	}
	UpdateUser(*userdata)
	return nil
}

func (userdata *User) AccessInvitation(fileInfo FileInfo) (UUID uuid.UUID, rootFileKey []byte, version int, err error) {
	/* Acces an invitation information from a file information struct
	to retrieve the file's root key */

	// Retrieve the invite uuid
	inviteUUID, err := uuid.FromBytes(userlib.Hash([]byte(fileInfo.FileName + fileInfo.Owner + userdata.Username))[:16])
	if err != nil {
		return UUID, rootFileKey, version, err
	}

	// Get the latest invitation from DataStore
	dataEntry, exist := userlib.DatastoreGet(inviteUUID)
	if !exist {
		return UUID, rootFileKey, version, errors.New("access revoked")
	}

	var publicKey userlib.PublicKeyType

	publicKey, exist = userlib.KeystoreGet(fileInfo.Owner)
	if !exist {
		return UUID, rootFileKey, version, errors.New("owner of the file does not exist")
	}

	// Verify sig and decrypt the marshlled invitation
	plainText, err := decInvite(dataEntry, publicKey, userdata.PrivateKey)
	if err != nil {
		publicKey, exist = userlib.KeystoreGet(fileInfo.Sender)
		if !exist {
			return UUID, rootFileKey, version, errors.New("sender of the file does not exist")
		}

		plainText, err = decInvite(dataEntry, publicKey, userdata.PrivateKey)
		if err != nil {
			return UUID, rootFileKey, version, err
		}
	}

	// Unmarshal the inviation
	var invitation Invitation
	err = json.Unmarshal(plainText, &invitation)
	if err != nil {
		return UUID, rootFileKey, version, err
	}

	return invitation.UUID, invitation.RootFileKey, invitation.Version, nil
}

func encInvite(invitation []byte, publicKey userlib.PublicKeyType, privateKey userlib.PrivateKeyType) (dataEntry []byte, err error) {
	/* Auxiliary function to encrypt an invitation and return a
	data entry struct to be stored in the intended uuid */

	// Set basic invitation variables
	var encInvitation EncInvitation

	// Encrypt 1st half
	encInvitation.CipherA, err = userlib.PKEEnc(publicKey, invitation[:len(invitation)/2])
	if err != nil {
		return dataEntry, err
	}

	// Encrypt 2nd half
	encInvitation.CipherB, err = userlib.PKEEnc(publicKey, invitation[len(invitation)/2:])
	if err != nil {
		return dataEntry, err
	}

	// Generate 1st signature
	castedDSSignPrivate := userlib.DSSignKey(privateKey)
	castedDSSignPrivate.KeyType = "DS"
	encInvitation.SigA, err = userlib.DSSign(castedDSSignPrivate, encInvitation.CipherA)
	if err != nil {
		return dataEntry, err
	}

	// Generate 2nd signature
	encInvitation.SigB, err = userlib.DSSign(castedDSSignPrivate, encInvitation.CipherB)
	if err != nil {
		return dataEntry, err
	}

	// Marshal the EncInvitation struct
	dataEntry, err = json.Marshal(encInvitation)
	if err != nil {
		return dataEntry, err
	}

	return dataEntry, nil
}

func decInvite(dataEntry []byte, publicKey userlib.PublicKeyType, privateKey userlib.PrivateKeyType) (plainText []byte, err error) {
	/* Auxiliary function to decrypt an invitation and return a
	plain text response to be read by invited user */

	// Set basic invitation variables
	var encInvitation EncInvitation
	err = json.Unmarshal(dataEntry, &encInvitation)
	if err != nil {
		return plainText, err
	}

	// Verify the 1st signature
	castedDSSignPublic := userlib.DSVerifyKey(publicKey)
	castedDSSignPublic.KeyType = "DS"
	err = userlib.DSVerify(castedDSSignPublic, encInvitation.CipherA, encInvitation.SigA)
	if err != nil {
		return plainText, err
	}

	// Verify the 2nd signature
	err = userlib.DSVerify(castedDSSignPublic, encInvitation.CipherB, encInvitation.SigB)
	if err != nil {
		return plainText, err
	}

	// Decrypt the 1st half invitation
	plainTextA, err := userlib.PKEDec(privateKey, encInvitation.CipherA)
	if err != nil {
		return plainText, err
	}

	// Decrypt the 2nd half invitation
	plainTextB, err := userlib.PKEDec(privateKey, encInvitation.CipherB)
	if err != nil {
		return plainText, err
	}

	// Append both invitation elements
	plainText = append(plainTextA, plainTextB...)

	// Return plain text information
	return plainText, nil
}
