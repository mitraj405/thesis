// SPDX-License-Identifier: BSD-3-Clause-Clear

pragma solidity 0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

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

    function setIdentifierBool(
        string memory did,
        string memory identifier,
        bytes calldata encryptedValue
    ) public onlyOwner {
        ebool value = TFHE.asEbool(encryptedValue);
        setIdentifierBool(did, identifier, value);
    }

    function setIdentifierBool(string memory did, string memory identifier, ebool value) public onlyOwner {
        Identifier storage ident = identities[did].identifiers[identifier];
        ident.encryptedBool = value;
    }

    function setIdentifier32(
        string memory did,
        string memory identifier,
        bytes calldata encryptedValue
    ) public onlyOwner {
        euint32 value = TFHE.asEuint32(encryptedValue);
        setIdentifier32(did, identifier, value);
    }

    function setIdentifier32(string memory did, string memory identifier, euint32 value) public onlyOwner {
        Identifier storage ident = identities[did].identifiers[identifier];
        ident.encrypted32 = value;
    }

    function getIdentifier(
        string memory did,
        string memory identifier,
        bytes calldata signature
    ) public view returns (Identifier memory) {
        Identifier storage ident = _getIdentifier(did, identifier, signature);
        return ident;
    }

    function getIdentifier(
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

    function _getIdentifier(
        string memory did,
        string memory identifier,
        bytes calldata signature
    ) internal view onlyAllowedUser(did, identifier, signature) returns (Identifier storage) {
        require(identities[did].owner != address(0), "DID doesn't exist");
        return identities[did].identifiers[identifier];
    }

    modifier onlyAllowedUser(
        string memory did,
        string memory identifier,
        bytes calldata signature
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
