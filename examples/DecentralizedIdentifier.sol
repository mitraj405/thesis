// SPDX-License-Identifier: BSD-3-Clause-Clear

pragma solidity 0.8.19;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

import "../abstracts/EIP712WithModifier.sol";

import "../lib/TFHE.sol";

contract DecentralizedId is EIP712WithModifier {
    // A mapping from address to an encrypted balance.
    mapping(string => Identity) internal identities;

    struct Identity {
        address owner;
        string did;
        mapping(string => euint32) identifiers;
    }

    // The owner of the contract.
    address public contractOwner;

    event NewDid(string did, address owner);

    constructor() EIP712WithModifier("Authorization token", "1") {
        contractOwner = msg.sender;
    }

    function registerDID(address owner) public onlyOrganization {
        string memory prefix = "did:zama:";
        string memory hash = Strings.toString(
            uint160(uint(keccak256(abi.encodePacked(owner, blockhash(block.number)))))
        );
        string memory did = string.concat(prefix, hash);
        Identity storage newIdentity = identities[did];
        newIdentity.owner = owner;
        newIdentity.did = did;

        emit NewDid(did, owner);
    }

    function setIdentifier(
        string memory did,
        string memory identifier,
        bytes calldata encryptedValue
    ) public onlyOrganization {
        euint32 value = TFHE.asEuint32(encryptedValue);
        setIdentifier(did, identifier, value);
    }

    function setIdentifier(string memory did, string memory identifier, euint32 value) public onlyOrganization {
        identities[did].identifiers[identifier] = value;
    }

    function getIdentifier(
        string memory did,
        string memory identifier,
        bytes calldata signature
    ) public view returns (euint32) {
        return _getIdentifier(did, identifier, signature);
    }

    // Sets the balance of the owner to the given encrypted balance.
    function getIdentifier(
        string memory did,
        string memory identifier,
        bytes calldata sign,
        bytes32 publicKey,
        bytes calldata signature
    ) public view onlySignedPublicKey(publicKey, signature) returns (bytes memory) {
        return TFHE.reencrypt(_getIdentifier(did, identifier, sign), publicKey, 0);
    }

    // Sets the balance of the owner to the given encrypted balance.
    function _getIdentifier(
        string memory did,
        string memory identifier,
        bytes calldata signature
    ) internal view onlyAllowedUser(did, identifier, signature) returns (euint32) {
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

    modifier onlyOrganization() {
        require(msg.sender == contractOwner);
        _;
    }
}
