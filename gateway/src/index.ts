import { CcipReadRouter } from '@ensdomains/ccip-read-router';
import { StandardMerkleTree } from '@openzeppelin/merkle-tree';
import {
  createPublicClient,
  http,
  PublicClient,
  Hex,
  keccak256,
  encodeAbiParameters,
  parseAbiParameters,
} from 'viem';
import { mainnet } from 'viem/chains';
import 'dotenv/config';

const client: PublicClient = createPublicClient({
  chain: mainnet,
  transport: http(process.env.NODE_PROVIDER as string),
});

const router = CcipReadRouter();

// handle storage layout verification
router.add({
  type: 'function verifyStorageLayout(address,bytes32,uint256) public view returns (bytes)',
  handle: async ([contractAddress, slot, value]): Promise<Hex> => {
    const storageSlot = await client.getStorageAt({
      address: contractAddress,
      slot: slot,
    });

    if (!storageSlot) {
      throw { error: 'Failed to fetch storage' };
    }

    // convert the fetched storage value to BigInt
    const fetchedValue = BigInt(storageSlot);

    // check if the fetched value matches the value provided in the request
    if (fetchedValue !== value) {
      throw { error: 'Mismatched storage value' };
    }

    // enerate merkle proof for the requested slot and value
    const storageLayout: [Hex, bigint][] = [[slot, value]];
    const { proof, leaf, root } = generateMerkleProof(
      storageLayout,
      slot,
      value
    );

    const encoded = encodeAbiParameters(
      parseAbiParameters('(bytes32[], bytes32, bytes32)'),
      [[proof, leaf, root]]
    );

    return encoded;
  },
});

// generate Merkle proof for given storage layout, slot, and value
function generateMerkleProof(
  storageLayout: [Hex, bigint][],
  slot: Hex,
  value: bigint
): { proof: Hex[]; leaf: Hex; root: Hex } {
  // generate merkle tree from the storage layout
  const tree = StandardMerkleTree.of(storageLayout, ['bytes32', 'uint256']);

  const leaf = keccak256(
    encodeAbiParameters(parseAbiParameters('bytes32, uint256'), [slot, value])
  );

  // Find the proof for the specific leaf
  let proof: Hex[] = [];
  for (const [i, v] of tree.entries()) {
    if (v[0] === slot && BigInt(v[1]) === value) {
      proof = tree.getProof(i).map((p) => p as Hex);
      break;
    }
  }

  return { proof, leaf, root: tree.root as Hex };
}

export default { ...router };
