First add Zama Devnet in to your meta mask wallet

Network Name      Zama Network
New RPC URL       https://devnet.zama.ai
Chain ID          8009
Currency symbol   ZAMA
Block URL         https://main.explorer.zama.ai

You can get 10 Zama token on https://faucet.zama.ai/

upload all files and folders in remix IDE
set solidity compiler to 0.8.19
set DEPLOY & RUN TRANSACTIONS environment to METAMASK

make a new example file, which you want to execute
suppose in my case, below is the solidity file i want to execute

--------------------------------------------------------------------------------------------------------

// SPDX-License-Identifier: BSD-3-Clause-Clear

pragma solidity  0.8.19;

import "fhevm/lib/TFHE.sol";

contract Counter {
  euint32 public  counter;
 // bytes memory dummyEncryptedValue = abi.encodePacked(uint32(42)); // Encrypt the value 42
  function add() public {
    counter = TFHE.asEuint32((uint32(42)));
    counter = counter + TFHE.asEuint32((uint32(42)));
  }

  function getTotalSupply() public view returns (uint32) {
  return TFHE.decrypt(counter);
}
}

--------------------------------------------------------------------------------------------------------

( in this example , i am encrypting 42, and then adding in to counter with tfhe )
then compile and deploy and you are ready to go !!
