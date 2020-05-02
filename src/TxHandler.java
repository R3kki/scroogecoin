import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashSet;

public class TxHandler {

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    private final UTXOPool currentPool;
    private final HashSet<Transaction.Output> currentPoolOutputs;

    public TxHandler(UTXOPool utxoPool) {
        currentPool = new UTXOPool(utxoPool);
        //  stores all outputs of current UTXOPool in a hashset to be easily checked
        currentPoolOutputs = new HashSet<>();
        for (UTXO ut : currentPool.getAllUTXO()) {
            currentPoolOutputs.add(currentPool.getTxOutput(ut));
        }
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool,
     * (2) the signatures on each input of {@code tx} are valid,
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     * values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        // (1)
        for (Transaction.Output output : tx.getOutputs()) {
            if (!currentPoolOutputs.contains(output)) return false;
        }

        // (2)
        for (Transaction.Input input : tx.getInputs()) {
            int index = input.outputIndex;
            byte[] signature = input.signature;
            Transaction.Output output = tx.getOutput(index); // corresponding output
            PublicKey pubKey = output.address;
            byte[] message = tx.getRawDataToSign(index);
            if (!Crypto.verifySignature(pubKey, message, signature)) return false;
        }
        // (3)
        for (Transaction.Output output : tx.getOutputs()) {
            if (!currentPoolOutputs.contains(output)) return false;
            currentPoolOutputs.remove(output);
        }
        // (4)
        for (Transaction.Output output : tx.getOutputs()) {
            if (output.value < 0) return false;
        }
        // (5)
        double inputSum = 0, outputSum = 0;
        for (Transaction.Input input : tx.getInputs()) {
            byte[] hash = input.prevTxHash;
            int index = input.outputIndex;
            double value = 0;
            for (UTXO utxo : currentPool.getAllUTXO()) {
                if (Arrays.equals(utxo.getTxHash(), hash) && utxo.getIndex() == index) {
                    value = currentPool.getTxOutput(utxo).value;
                    break;
                }
            }
            inputSum += value;
        }
        for (Transaction.Output output : tx.getOutputs()) {
            outputSum += output.value;
        }

        return !(inputSum < outputSum);
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        // IMPLEMENT THIS
    }

}
