// SPDX-License-Identifier: BSD-3-Clause-Clear

pragma solidity 0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import "../abstracts/EIP712WithModifier.sol";

import "../lib/TFHE.sol";

contract DecentralizedId is EIP712WithModifier, Ownable {
    // A mapping from did to an identity.
    mapping(string => Identity) internal identities;

    struct Identity {
        address owner;
        string did;
        mapping(string => Identifier) identifiers;
    }

    struct Identifier {
        euint32 encrypted32;
        ebool encryptedBool;
        string text;
    }

    event NewDid(string did, address owner);
    event RemoveDid(string did);

    constructor() EIP712WithModifier("Authorization token", "1") {}

    function addId(string calldata did, address owner) public onlyOwner {
        require(identities[did].owner == address(0), "This did already exists");
        Identity storage newIdentity = identities[did];
        newIdentity.owner = owner;
        newIdentity.did = did;

        emit NewDid(did, owner);
    }

    function removeId(string calldata did) public onlyOwner {
        require(identities[did].owner != address(0), "This did doesn't exist");
        delete identities[did];

        emit RemoveDid(did);
    }

    function getOwner(string calldata did) public view returns (address) {
        return identities[did].owner;
    }

    function changeOwner(string calldata did, address newOwner) public onlyOwner {
        identities[did].owner = newOwner;
    }

    function setIdentifier(string calldata did, string calldata identifier, string calldata value) public onlyOwner {
        delete identities[did].identifiers[identifier];
        Identifier storage ident = identities[did].identifiers[identifier];
        ident.text = value;
    }

    function setIdentifierBool(string calldata did, string calldata identifier, bytes calldata encryptedValue) public {
        ebool value = TFHE.asEbool(encryptedValue);
        setIdentifierBool(did, identifier, value);
    }

    function setIdentifierBool(string calldata did, string calldata identifier, ebool value) public onlyOwner {
        delete identities[did].identifiers[identifier];
        Identifier storage ident = identities[did].identifiers[identifier];
        ident.encryptedBool = value;
    }

    function setIdentifier32(string calldata did, string calldata identifier, bytes calldata encryptedValue) public {
        euint32 value = TFHE.asEuint32(encryptedValue);
        setIdentifier32(did, identifier, value);
    }

    function setIdentifier32(string calldata did, string calldata identifier, euint32 value) public onlyOwner {
        delete identities[did].identifiers[identifier];
        Identifier storage ident = identities[did].identifiers[identifier];
        ident.encrypted32 = value;
    }

    function getIdentifier(string calldata did, string calldata identifier) public view returns (string memory) {
        Identifier storage ident = identities[did].identifiers[identifier];
        require(bytes(ident.text).length > 0, "This identifier is unknown");

        return ident.text;
    }

    function reencryptIdentifier(
        string calldata did,
        string calldata identifier,
        bytes calldata sign,
        bytes32 publicKey,
        bytes calldata signature
    ) public view onlySignedPublicKey(publicKey, signature) returns (bytes memory) {
        Identifier storage ident = _getIdentifier(did, identifier, sign);
        require(
            TFHE.isInitialized(ident.encrypted32) || ebool.unwrap(ident.encryptedBool) != 0,
            "This identifier is unknown"
        );

        if (TFHE.isInitialized(ident.encrypted32)) {
            return TFHE.reencrypt(ident.encrypted32, publicKey, 0);
        }

        return TFHE.reencrypt(ident.encryptedBool, publicKey);
    }

    function getEboolIdentifier(
        string calldata did,
        string calldata identifier,
        bytes calldata signature
    ) public view returns (ebool) {
        Identifier storage ident = _getIdentifier(did, identifier, signature);
        require(ebool.unwrap(ident.encryptedBool) != 0, "This identifier is unknown");
        return ident.encryptedBool;
    }

    function getEuint32Identifier(
        string calldata did,
        string calldata identifier,
        bytes calldata signature
    ) public view returns (euint32) {
        Identifier storage ident = _getIdentifier(did, identifier, signature);
        require(TFHE.isInitialized(ident.encrypted32), "This identifier is unknown");
        return ident.encrypted32;
    }

    function _getIdentifier(
        string calldata did,
        string calldata identifier,
        bytes calldata signature
    ) internal view onlyAllowedUser(did, identifier, signature) returns (Identifier storage) {
        require(identities[did].owner != address(0), "DID doesn't exist");
        return identities[did].identifiers[identifier];
    }

    modifier onlyAllowedUser(
        string calldata did,
        string memory identifier,
        bytes memory signature
    ) {
        require(identities[did].owner != address(0), "DID doesn't exist");
        address user = identities[did].owner;
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    keccak256("DecentralizedId(string identifier,address allowed)"),
                    keccak256(abi.encodePacked(identifier)),
                    msg.sender
                )
            )
        );
        address signer = ECDSA.recover(digest, signature);
        require(signer == user, "You don't have access");
        _;
    }
}
