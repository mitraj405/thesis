// SPDX-License-Identifier: BSD-3-Clause-Clear

pragma solidity >=0.8.13 <0.9.0;

import "./Precompiles.sol";
import "./Common.sol";

// A library of functions for managing ciphertexts.
library Ciphertext {
    // The maximum ciphertext output length in bytes.
    // Rationale: `bytes` ciphertext layout is 32 bytes of length metadata, followed by 65544 bytes of ciphertext.
    uint256 constant MaxCiphertextBytesLen = 32 + 65544;

    // Reencrypt the given `ciphertext` to the original caller's public key.
    // If successful, return the reencrypted ciphertext bytes. Else, fail.
    // Currently, can only be used in `eth_call`. If called in a transaction, it will fail.
    function reencrypt(
        FHEUInt ciphertext
    ) internal view returns (bytes memory reencrypted) {
        bytes32[1] memory input;
        input[0] = bytes32(FHEUInt.unwrap(ciphertext));
        uint256 inputLen = 32;
        reencrypted = new bytes(MaxCiphertextBytesLen);

        // Call the reencrypt precompile.
        uint256 precompile = Precompiles.Reencrypt;
        assembly {
            if iszero(
                staticcall(
                    gas(),
                    precompile,
                    input,
                    inputLen,
                    reencrypted,
                    MaxCiphertextBytesLen
                )
            ) {
                revert(0, 0)
            }
        }
    }

    // Verify the proof of the given `ciphertextWithProof`.
    // If successful, return the ciphertxt. Else, fail.
    // It is expected that the ciphertext is serialized such that it contains a zero-knowledge proof of knowledge of the plaintext.
    function verify(
        bytes memory ciphertextWithProof
    ) internal view returns (FHEUInt ciphertext) {
        bytes32[1] memory output;
        uint256 outputLen = 32;
        uint256 inputLen = ciphertextWithProof.length;

        // Call the verify precompile. Skip 32 bytes of lenght metadata for the input `bytes`.
        uint256 precompile = Precompiles.Verify;
        assembly {
            if iszero(
                staticcall(
                    gas(),
                    precompile,
                    add(ciphertextWithProof, 32),
                    inputLen,
                    output,
                    outputLen
                )
            ) {
                revert(0, 0)
            }
        }

        ciphertext = FHEUInt.wrap(uint256(output[0]));
    }

    // Delegate the given `ciphertext` for use in the outer scope.
    // If successful, return. Else, fail.
    function delegate(FHEUInt ciphertext) internal view {
        bytes32[1] memory input;
        input[0] = bytes32(FHEUInt.unwrap(ciphertext));
        uint256 inputLen = 32;

        // Call the delegate precompile.
        uint256 precompile = Precompiles.Delegate;
        assembly {
            if iszero(staticcall(gas(), precompile, input, inputLen, 0, 0)) {
                revert(0, 0)
            }
        }
    }

    function from(uint8 to_encrypt) internal view returns (FHEUInt ciphertext) {
        bytes1 input;
        input = bytes1(to_encrypt);
        uint256 inputLen = 1;

        bytes32[1] memory output;
        uint256 outputLen = 32;

        // Call the from precompile.
        uint256 precompile = Precompiles.From;
        assembly {
            if iszero(
                staticcall(
                    gas(),
                    precompile,
                    input,
                    inputLen,
                    output,
                    outputLen
                )
            ) {
                revert(0, 0)
            }
        }

        ciphertext = FHEUInt.wrap(uint256(output[0]));
    }
}
