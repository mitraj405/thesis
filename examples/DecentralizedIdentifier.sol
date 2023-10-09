// SPDX-License-Identifier: BSD-3-Clause-Clear

pragma solidity 0.8.19;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../abstracts/EIP712WithModifier.sol";

import "../lib/TFHE.sol";

contract DecentralizedId is EIP712WithModifier {
    // A mapping from address to an encrypted balance.
    mapping(address => mapping(string => euint32)) internal identifiers;

    // The owner of the contract.
    address public contractOwner;

    constructor() EIP712WithModifier("Authorization token", "1") {
        contractOwner = msg.sender;
    }

    function setIdentifier(address user, string calldata name, bytes calldata encryptedValue) public onlyContractOwner {
        euint32 value = TFHE.asEuint32(encryptedValue);
        setIdentifier(user, name, value);
    }

    function setIdentifier(address user, string calldata name, euint32 value) public onlyContractOwner {
        identifiers[user][name] = value;
    }

    function getIdentifier(address user, string calldata name, bytes calldata signature) public view returns (euint32) {
        return _getIdentifier(user, name, signature);
    }

    // Sets the balance of the owner to the given encrypted balance.
    function getIdentifier(
        address user,
        string calldata identifier,
        bytes calldata sign,
        bytes32 publicKey,
        bytes calldata signature
    ) public view onlySignedPublicKey(publicKey, signature) returns (bytes memory) {
        return TFHE.reencrypt(_getIdentifier(user, identifier, sign), publicKey, 0);
    }

    // Sets the balance of the owner to the given encrypted balance.
    function _getIdentifier(
        address user,
        string calldata identifier,
        bytes calldata signature
    ) internal view onlyAllowedUser(user, identifier, signature) returns (euint32) {
        return identifiers[user][identifier];
    }

    modifier onlyAllowedUser(
        address user,
        string calldata identifier,
        bytes calldata signature
    ) {
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

    modifier onlyContractOwner() {
        require(msg.sender == contractOwner);
        _;
    }
}
