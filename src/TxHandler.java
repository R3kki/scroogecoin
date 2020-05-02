import java.security.PublicKey;
import java.util.ArrayList;
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
        for (Transaction.Output output : tx.getOutputs())
            if (!currentPoolOutputs.contains(output)) return false;

        // (2)
        for (Transaction.Input input : tx.getInputs()) {
            // input
            int index = input.outputIndex;
            byte[] signature = input.signature;
            Transaction.Output output = correspondingOutput(input);
            // spent output
            PublicKey pubKey = output.address;
            byte[] message = tx.getRawDataToSign(index);
            // verify
            if (!Crypto.verifySignature(pubKey, message, signature)) return false;
        }
        // (3)
        for (Transaction.Output output : tx.getOutputs()) {
            if (!currentPoolOutputs.contains(output)) return false;
            currentPoolOutputs.remove(output);
        }
        // (4)
        for (Transaction.Output output : tx.getOutputs())
            if (output.value < 0) return false;

        // (5)
        double inputSum = 0, outputSum = 0;
        for (Transaction.Input input : tx.getInputs())
            inputSum += correspondingOutput(input).value;
        for (Transaction.Output output : tx.getOutputs())
            outputSum += output.value;

        return !(inputSum < outputSum);
    }

    private Transaction.Output correspondingOutput(Transaction.Input input) {
        Transaction.Output output = null;
        byte[] hash = input.prevTxHash;
        int index = input.outputIndex;
        for (UTXO ut : currentPool.getAllUTXO()) {
            if (Arrays.equals(ut.getTxHash(), hash) && ut.getIndex() == index) {
                output = currentPool.getTxOutput(ut);
                break;
            }
        }
        return output;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        ArrayList<Transaction> validTransactions = new ArrayList<>();

        // validate and add keep track of accepted transactions
        for (Transaction t : possibleTxs)
            if (isValidTx(t)) validTransactions.add(t);

        // update current UTXO pool
        int index = 0;
        Transaction[] acceptedTransactions = new Transaction[validTransactions.size()];
        for (Transaction t : validTransactions) {
            acceptedTransactions[index++] = t;
            byte[] txHash = t.getHash();
            // update the transaction outputs
            int txIndex = 0;
            for (Transaction.Output output : t.getOutputs()) {
                UTXO ut = new UTXO(txHash, txIndex++);
                currentPool.addUTXO(ut, output); // add to current UTXO Pool
            }
        }

        return acceptedTransactions;

    }

}
